package sshsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	pseudorand "math/rand"
	"net/textproto"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pardot/oidc"
	sshsigner "github.com/pardot/sshsigner/proto/sshsigner/v1alpha1"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	validAfterDurationSkew            = -1 * time.Minute
	defaultMaxUserSignedValidDuration = 15 * time.Minute
	defaultHostSignedValidDuration    = 24 * time.Hour

	nonceValidity = 24 * time.Hour
)

const (
	ACRMultiFactor         string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
	ACRMultiFactorPhysical string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"
	AMROTP                 string = "otp"
)

var _ sshsigner.SignerServer = (*SSHSigner)(nil)

// NonceRecorder is used to avoid replays
type NonceRecorder interface {
	// RecordNonce should note that a given nonce was used, and indicate if it
	// has already been used.
	RecordNonce(ctx context.Context, nonce string, expires time.Time) (used bool, err error)
}

// TokenVerifier is used to verify a given JWT, returning claim information
type TokenVerifier interface {
	VerifyRaw(ctx context.Context, audience string, rawToken string, opts ...oidc.VerifyOpt) (*oidc.Claims, error)
}

// SignerSource is used to retrieve a signer for signing operations, and
// information about public keys considered valid for this source. This can be
// used to wrap multiple signers / other keysets for use by this service
type SignerSource interface {
	// Signer should return a usable crypto.Signer, that will be used for a
	// signing operations.
	Signer(context.Context) (crypto.Signer, error)
	// PublicKeys returns a list of all public keys that should be considered
	// valid for this source.
	PublicKeys(context.Context) ([]crypto.PublicKey, error)
}

type staticSignerSource struct {
	signer   crypto.Signer
	addlKeys []crypto.PublicKey
}

func (s *staticSignerSource) Signer(context.Context) (crypto.Signer, error) {
	return s.signer, nil
}

func (s *staticSignerSource) PublicKeys(context.Context) ([]crypto.PublicKey, error) {
	return append([]crypto.PublicKey{s.signer.Public()}, s.addlKeys...), nil
}

// NewStaticSignerSource returns a simple SignerSource that is bound to a single
// key
func NewStaticSignerSource(s crypto.Signer, addlKeys ...crypto.PublicKey) SignerSource {
	return &staticSignerSource{
		signer:   s,
		addlKeys: addlKeys,
	}
}

type SignerOpt func(s *SSHSigner)

type SSHSigner struct {
	Log logrus.FieldLogger

	hostSignerSource SignerSource
	userSignerSource SignerSource

	remoteCacheFor   time.Duration
	remoteCacheSplay time.Duration
	rand             *pseudorand.Rand

	userCertValidForMax time.Duration
	hostCertValidFor    time.Duration

	NonceRec NonceRecorder

	Verifier         TokenVerifier
	Audience         string
	ValidAWSAccounts []string

	clock func() time.Time
}

// WithHostCertValidityPeriod sets the duration that host certs are valid for,
// after signing time. The default is 24 hours.
func WithHostCertValidityPeriod(p time.Duration) SignerOpt {
	return func(s *SSHSigner) {
		s.hostCertValidFor = p
	}
}

// WithMaxUserCertValidityPeriod sets the maximum duration that user certs are
// valid for, after signing time. The default is 15 minutes. If the submitted
// claims expire in a time less than this, that time will be used instead.
func WithMaxUserCertValidityPeriod(p time.Duration) SignerOpt {
	return func(s *SSHSigner) {
		s.userCertValidForMax = p
	}
}

// WithSignersCache will cache results for public key lookups for a fixed time.
// This can be used to reduce load for the public key endpoints
func WithSignersCache(cacheFor time.Duration) SignerOpt {
	return func(s *SSHSigner) {
		s.userSignerSource = &cacheKeySource{
			SignerSource: s.userSignerSource,
			CacheFor:     cacheFor,
		}
		s.hostSignerSource = &cacheKeySource{
			SignerSource: s.hostSignerSource,
			CacheFor:     cacheFor,
		}
	}
}

// WithCacheControl will return a Cache-Control header on requests to the
// user/host signing keys endpoint. This can be used for server control of how
// often the client fetches keys. The header is marked private, so intermediate
// proxies will ignore this. Max-Age will be set to the maxAge value, plus up to
// splay time.
func WithCacheControl(maxAge, splay time.Duration) SignerOpt {
	return func(s *SSHSigner) {
		s.remoteCacheFor = maxAge
		s.remoteCacheSplay = splay
		s.rand = pseudorand.New(pseudorand.NewSource(time.Now().UnixNano() ^ int64(os.Getpid())))
	}
}

func New(l logrus.FieldLogger, userSigner SignerSource, hostSigner SignerSource, nonceRec NonceRecorder, v TokenVerifier, aud string, validAWSAccounts []string, opts ...SignerOpt) (*SSHSigner, error) {
	ss := &SSHSigner{
		Log:                 l.WithField("component", "sshsigner"),
		Verifier:            v,
		Audience:            aud,
		ValidAWSAccounts:    validAWSAccounts,
		NonceRec:            nonceRec,
		userSignerSource:    userSigner,
		hostSignerSource:    hostSigner,
		userCertValidForMax: defaultMaxUserSignedValidDuration,
		hostCertValidFor:    defaultHostSignedValidDuration,
	}

	for _, o := range opts {
		o(ss)
	}

	return ss, nil
}

func (s *SSHSigner) SignUserKey(ctx context.Context, req *sshsigner.SignUserKeyRequest) (*sshsigner.SignUserKeyResponse, error) {
	logger := s.Log.WithFields(logrus.Fields{
		"fn":        "SignUserKey",
		"ip":        remoteAddrFromContext(ctx),
		"publickey": req.PublicKey,
	})

	claims, err := s.authRequest(ctx)
	if err != nil {
		logger.WithError(err).WithField("at", "auth-request-error").Error()
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if awsI, ok := claims.Extra["awsInstance"].(bool); ok && awsI {
		return nil, status.Error(codes.PermissionDenied, "only users may use this RPC")
	}

	gc := groupClaims{}
	if err := claims.Unmarshal(&gc); err != nil {
		logger.WithError(err).WithField("at", "unmarshal-claims").Error()
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	if len(gc.Groups) == 0 {
		return nil, status.Error(codes.PermissionDenied, "user must be member of at least one group")
	}

	email, _ := claims.Extra["email"].(string)
	name, _ := claims.Extra["name"].(string)

	logger = logger.WithFields(logrus.Fields{
		"subject":  claims.Subject,
		"username": name,
		"email":    email,
		"nonce":    claims.Nonce,
	})

	nonce := claims.Nonce
	if len(nonce) == 0 {
		return nil, status.Error(codes.PermissionDenied, "empty nonce")
	}
	used, err := s.NonceRec.RecordNonce(ctx, nonce, time.Now().Add(nonceValidity))
	if err != nil {
		logger.WithError(err).WithField("at", "record-nonce-error").Error()
		return nil, status.Error(codes.Internal, "failed to record nonce")
	} else if used {
		logger.WithError(err).WithField("at", "nonce-replay").Warn()
		return nil, status.Error(codes.PermissionDenied, "invalid nonce")
	}

	principals := []string{}

	// Groups are embedded as principals in the form group:%s
	for _, group := range gc.Groups {
		principals = append(principals, fmt.Sprintf("group:%s", group))
	}

	// ACR and AMR are embedded as principals in the form acr:%s and amr:%s.
	// This allows some servers to require MFA (e.g., in production) while
	// others do not (e.g., in non-production) without having separate
	// signers.
	if claims.ACR != "" {
		principals = append(principals, fmt.Sprintf("acr:%s", claims.ACR))

		for _, amr := range claims.AMR {
			principals = append(principals, fmt.Sprintf("amr:%s", amr))
		}
	}

	logger = logger.WithField("principals", principals)

	now := s.now()
	validBefore := now.Add(s.userCertValidForMax)
	if claims.Expiry.Time().Before(validBefore) {
		validBefore = claims.Expiry.Time()
	}

	sreq := sshCertReq{
		CertType:    ssh.UserCert,
		Key:         []byte(req.PublicKey),
		ID:          claims.Subject,
		Principals:  principals,
		ValidAfter:  now.Add(validAfterDurationSkew),
		ValidBefore: validBefore,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	signer, err := s.userSignerSource.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %v", err)
	}

	signed, err := signRequest(signer, sreq)
	if err != nil {
		logger.WithError(err).WithField("at", "sign-request-failed").Error()
		return nil, status.Errorf(codes.Internal, "failed to sign user key")
	}

	logger.WithField("at", "success").Info()

	return &sshsigner.SignUserKeyResponse{SignedCertificate: signed}, nil
}

func (s *SSHSigner) SignHostKey(ctx context.Context, req *sshsigner.SignHostKeyRequest) (*sshsigner.SignHostKeyResponse, error) {
	logger := s.Log.WithFields(logrus.Fields{
		"fn":        "SignHostKey",
		"ip":        remoteAddrFromContext(ctx),
		"publickey": req.PublicKey,
		"hostnames": req.Hostnames,
	})

	claims, err := s.authRequest(ctx)
	if err != nil {
		logger.WithError(err).WithField("at", "auth-request-error").Error()
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	nonce := claims.Nonce
	if len(nonce) == 0 {
		return nil, status.Error(codes.PermissionDenied, "empty nonce")
	}
	used, err := s.NonceRec.RecordNonce(ctx, nonce, time.Now().Add(nonceValidity))
	if err != nil {
		logger.WithError(err).WithField("at", "record-nonce-error").Error()
		return nil, status.Error(codes.Internal, "failed to record nonce")
	} else if used {
		logger.WithError(err).WithField("at", "nonce-replay").Warn()
		return nil, status.Error(codes.PermissionDenied, "invalid nonce")
	}

	if awsI, ok := claims.Extra["awsInstance"].(bool); !ok || !awsI {
		return nil, status.Error(codes.PermissionDenied, "only AWS roles may use this RPC")
	}

	arnc, _ := claims.Extra["arn"].(string)
	md, _ := claims.Extra["md"].(map[string]interface{})

	logger = logger.WithFields(logrus.Fields{
		"subject":  claims.Subject,
		"arn":      arnc,
		"metadata": md,
		"nonce":    claims.Nonce,
	})

	if len(req.Hostnames) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one hostname must be specified")
	}

	parn, err := arn.Parse(arnc)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid ARN")
	}

	if parn.Partition != "aws" {
		logger.WithField("at", "not-valid-partition").Error()
		return nil, status.Error(codes.PermissionDenied, "invalid ARN")
	} else if parn.Service != "sts" {
		logger.WithField("at", "not-valid-service").Error()
		return nil, status.Error(codes.PermissionDenied, "invalid ARN")
	} else if !strings.HasPrefix(parn.Resource, "assumed-role/aws:ec2-instance/") {
		logger.WithField("at", "not-valid-resource").Error()
		return nil, status.Error(codes.PermissionDenied, "invalid ARN")
	}

	var validAWSAccount bool
	for _, awsAccount := range s.ValidAWSAccounts {
		if awsAccount == parn.AccountID {
			validAWSAccount = true
			break
		}
	}
	if !validAWSAccount {
		logger.WithField("at", "not-valid-account").WithField("account", parn.AccountID).Error()
		return nil, status.Error(codes.PermissionDenied, "invalid ARN")
	}

	principals := req.Hostnames
	logger = logger.WithField("principals", principals)

	now := s.now()
	sreq := sshCertReq{
		CertType:    ssh.HostCert,
		Key:         []byte(req.PublicKey),
		ID:          parn.String(),
		Principals:  principals,
		ValidAfter:  now.Add(validAfterDurationSkew),
		ValidBefore: now.Add(s.hostCertValidFor),
	}

	signer, err := s.hostSignerSource.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting signer: %v", err)
	}

	signed, err := signRequest(signer, sreq)
	if err != nil {
		logger.WithError(err).WithField("at", "sign-request-failed").Error()
		return nil, status.Errorf(codes.Internal, "failed to sign host key")
	}

	logger.WithField("at", "success").Info()

	return &sshsigner.SignHostKeyResponse{SignedCertificate: signed}, nil
}

func (s *SSHSigner) UserSigners(ctx context.Context, _ *empty.Empty) (*sshsigner.UserSignersResponse, error) {
	logger := s.Log.WithFields(logrus.Fields{
		"fn": "UserSigners",
		"ip": remoteAddrFromContext(ctx),
	})

	keys, err := validAuthKeys(ctx, s.userSignerSource)
	if err != nil {
		logger.WithError(err).WithField("at", "get-ssh-keyset-error").Error()
		return nil, status.Errorf(codes.Internal, "failed to retrieve keyset")
	}

	resp := &sshsigner.UserSignersResponse{}

	for _, k := range keys {
		resp.VerificationKeys = append(resp.VerificationKeys, &sshsigner.VerificationKey{
			Key: ssh.MarshalAuthorizedKey(k),
		})
	}

	if err := grpc.SendHeader(ctx, s.cacheControlMD()); err != nil {
		logger.WithError(err).WithField("at", "send-cache-control-metadata").Error()
		return nil, status.Errorf(codes.Internal, "failed to retrieve keyset")
	}

	return resp, nil
}

func (s *SSHSigner) HostSigners(ctx context.Context, _ *empty.Empty) (*sshsigner.HostSignersResponse, error) {
	logger := s.Log.WithFields(logrus.Fields{
		"fn": "HostSigners",
		"ip": remoteAddrFromContext(ctx),
	})

	keys, err := validAuthKeys(ctx, s.hostSignerSource)
	if err != nil {
		logger.WithError(err).WithField("at", "get-ssh-keyset-error").Error()
		return nil, status.Errorf(codes.Internal, "failed to retrieve keyset")
	}

	resp := &sshsigner.HostSignersResponse{}

	for _, k := range keys {
		resp.VerificationKeys = append(resp.VerificationKeys, &sshsigner.VerificationKey{
			Key: ssh.MarshalAuthorizedKey(k),
		})
	}

	if err := grpc.SendHeader(ctx, s.cacheControlMD()); err != nil {
		logger.WithError(err).WithField("at", "send-cache-control-metadata").Error()
		return nil, status.Errorf(codes.Internal, "failed to retrieve keyset")
	}

	return resp, nil
}

func (s *SSHSigner) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}

	return s.clock()
}

func (s *SSHSigner) authRequest(ctx context.Context) (*oidc.Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("metadata missing from incoming context")
	}

	authhdr := md.Get("authorization")
	if len(authhdr) != 1 {
		return nil, fmt.Errorf("want 1 authorization header, got %d", len(authhdr))
	}

	authsp := strings.SplitN(authhdr[0], " ", 2)
	if len(authsp) != 2 {
		return nil, fmt.Errorf("authorization header format incorrect")
	}

	if !strings.EqualFold(authsp[0], "bearer") {
		return nil, fmt.Errorf("provided authorization token is not a bearer token")
	}

	claims, err := s.Verifier.VerifyRaw(ctx, s.Audience, authsp[1])
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	return claims, nil
}

func (s *SSHSigner) cacheControlMD() metadata.MD {
	md := metadata.New(map[string]string{})
	if s.remoteCacheFor == 0 {
		return md
	}

	splayedInterval := time.Duration(int64(s.remoteCacheFor) + s.rand.Int63n(int64(s.remoteCacheSplay)))
	md.Set(textproto.CanonicalMIMEHeaderKey("Cache-Control"), fmt.Sprintf("private, max-age=%d", int64(splayedInterval.Seconds())))

	return md
}

type sshCertReq struct {
	// CertType of the certificate. Either ssh.UserCert or ssh.HostCert
	CertType uint32
	// Key to sign
	Key []byte
	// ID of the key. This is logged by OpenSSH. For user certificates, this is the
	// token subject, which encodes their Aloha User ID. For host certificates,
	// this is the IAM role that was assumed.
	ID string
	// Principals for the certificate. For user certificates, we use groups as
	// principals, allowing hosts to make authz decisions like "only ops may login
	// as root". For host certificates, this must be a list of hostnames, which the
	// client will validate.
	Principals  []string
	Permissions ssh.Permissions
	ValidAfter  time.Time
	ValidBefore time.Time
}

// technically this shouldn't work, because we're not changing the flagged cert
// type to `rsa-sha2-256-cert-v01`. But, there is an exception for this exact
// path for "legacy reasons" so we can get away with it
// https://github.com/openssh/openssh-portable/blob/11d427162778c18fa42917893a75d178679a2389/ssh-rsa.c#L274-L287
type sshAlgorithmSigner struct {
	algorithm string
	signer    ssh.AlgorithmSigner
}

func (s *sshAlgorithmSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func (s *sshAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.SignWithAlgorithm(rand, data, s.algorithm)
}

var signRequest = func(signer crypto.Signer, req sshCertReq) (string, error) {
	if len(req.Principals) == 0 {
		return "", fmt.Errorf("empty list of principals")
	}
	if len(req.ID) == 0 {
		return "", fmt.Errorf("empty ID")
	}
	if len(req.Key) == 0 {
		return "", fmt.Errorf("empty key")
	}

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	serial := binary.LittleEndian.Uint64(buf)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.Key))
	if err != nil {
		return "", fmt.Errorf("failed to parse user public key: %w", err)
	}

	certificate := ssh.Certificate{
		Serial:          serial,
		Key:             pubKey,
		KeyId:           req.ID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(req.ValidAfter.Unix()),
		ValidBefore:     uint64(req.ValidBefore.Unix()),
		CertType:        req.CertType,
		Permissions: ssh.Permissions{
			CriticalOptions: req.Permissions.CriticalOptions,
			Extensions:      req.Permissions.Extensions,
		},
	}

	ca, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return "", fmt.Errorf("creating ssh signer: %v", err)
	}

	as, ok := ca.(ssh.AlgorithmSigner)
	if !ok {
		return "", fmt.Errorf("SSH signer is not an algorithm signer, cannot proceed")
	}

	sas := &sshAlgorithmSigner{
		signer:    as,
		algorithm: ssh.SigAlgoRSASHA2256,
	}

	err = certificate.SignCert(rand.Reader, sas)
	if err != nil {
		return "", fmt.Errorf("failed to sign user public key: %s", err)
	}

	marshaledCertificate := ssh.MarshalAuthorizedKey(&certificate)
	if len(marshaledCertificate) == 0 {
		return "", errors.New("failed to marshal signed certificate, empty result")
	}

	return string(marshaledCertificate), nil
}

func remoteAddrFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	v := md.Get("x-forwarded-for")
	if len(v) == 0 {
		return ""
	}

	return v[0]
}

// validAuthKeys builds a list of valid SSH public keys from the signer, and the
// KeySource if non-nil
func validAuthKeys(ctx context.Context, ks SignerSource) ([]ssh.PublicKey, error) {
	keys := map[string]ssh.PublicKey{}

	if ks != nil {
		aks, err := ks.PublicKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching from KeySource: %v", err)
		}
		for _, k := range aks {
			sk, err := ssh.NewPublicKey(k)
			if err != nil {
				return nil, err
			}
			keys[string(sk.Marshal())] = sk
		}
	}

	ret := []ssh.PublicKey{}
	for _, v := range keys {
		ret = append(ret, v)
	}

	return ret, nil
}

type groupClaims struct {
	Groups []string `json:"groups"`
}

// cacheKeySource wraps a signer source, caching public key lookups
type cacheKeySource struct {
	SignerSource

	CacheFor time.Duration

	cached    []crypto.PublicKey
	nextFetch time.Time
	cacheMu   sync.RWMutex
}

func (c *cacheKeySource) PublicKeys(ctx context.Context) ([]crypto.PublicKey, error) {
	c.cacheMu.RLock()
	if time.Now().Before(c.nextFetch) && c.cached != nil {
		c.cacheMu.RUnlock()
		return c.cached, nil
	}

	// we have no cache, re-lock for writing
	c.cacheMu.RUnlock()
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// check again, in case another instance refreshed
	if time.Now().Before(c.nextFetch) && c.cached != nil {
		return c.cached, nil
	}

	// fetch
	curr, err := c.SignerSource.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	c.cached = curr
	c.nextFetch = time.Now().Add(c.CacheFor)

	return curr, err
}
