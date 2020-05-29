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
	validAfterDurationSkew     = -1 * time.Minute
	maxUserSignedValidDuration = 15 * time.Minute
	hostSignedValidDuration    = 24 * time.Hour

	nonceValidity = 24 * time.Hour
)

const (
	ACRMultiFactor         string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
	ACRMultiFactorPhysical string = "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"
	AMROTP                 string = "otp"
)

var _ sshsigner.SignerServer = (*SSHSigner)(nil)

// KeySource is an optional interface a Signer can implement. If it does, this
// will be called to retrieve additional valid public keys
type KeySource interface {
	PublicKeys(ctx context.Context) ([]crypto.PublicKey, error)
}

// NonceRecorder is used to avoid replays
type NonceRecorder interface {
	// RecordNonce should note that a given nonce was used, and indicate if it
	// has already been used.
	RecordNonce(ctx context.Context, nonce string, expires time.Time) (used bool, err error)
}

type TokenVerifier interface {
	VerifyRaw(ctx context.Context, audience string, raw string, opts ...oidc.VerifyOpt) (*oidc.Claims, error)
}

type SignerOpt func(s *SSHSigner)

type SSHSigner struct {
	Log logrus.FieldLogger

	hostSigner crypto.Signer
	userSigner crypto.Signer

	userKeySource KeySource
	hostKeySource KeySource

	remoteCacheFor   time.Duration
	remoteCacheSplay time.Duration
	rand             *pseudorand.Rand

	NonceRec NonceRecorder

	Verifier         TokenVerifier
	Audience         string
	ValidAWSAccounts []string

	clock func() time.Time
}

func WithUserKeysource(ks KeySource) SignerOpt {
	return func(s *SSHSigner) {
		s.userKeySource = ks
	}
}

func WithHostKeysource(ks KeySource) SignerOpt {
	return func(s *SSHSigner) {
		s.hostKeySource = ks
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

// WithSignersCache will cache results for keysource lookups in memory for the
// given time.
func WithSignersCache(cacheFor time.Duration) SignerOpt {
	return func(s *SSHSigner) {
		s.userKeySource = &cacheKeySource{
			Wrap:     s.userKeySource,
			CacheFor: cacheFor,
		}
		s.hostKeySource = &cacheKeySource{
			Wrap:     s.hostKeySource,
			CacheFor: cacheFor,
		}
	}
}

// SignerSource should return a configured crypto.Signer when called. The
// returned signer can also optionally implement the KeySource interface, if
// there is the potential for addition public keys to be considered valid.
type SignerSource func(ctx context.Context) (crypto.Signer, error)

func New(l logrus.FieldLogger, userSigner crypto.Signer, hostSigner crypto.Signer, nonceRec NonceRecorder, v TokenVerifier, aud string, validAWSAccounts []string, opts ...SignerOpt) (*SSHSigner, error) {
	ss := &SSHSigner{
		Log:              l.WithField("component", "sshsigner"),
		Verifier:         v,
		Audience:         aud,
		ValidAWSAccounts: validAWSAccounts,
		NonceRec:         nonceRec,
		userSigner:       userSigner,
		hostSigner:       hostSigner,
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
	validBefore := now.Add(maxUserSignedValidDuration)
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

	signed, err := signRequest(s.userSigner, sreq)
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
		ValidBefore: now.Add(hostSignedValidDuration),
	}

	signed, err := signRequest(s.hostSigner, sreq)
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

	keys, err := validAuthKeys(ctx, s.userSigner, s.userKeySource)
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

	keys, err := validAuthKeys(ctx, s.hostSigner, s.hostKeySource)
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
func validAuthKeys(ctx context.Context, s crypto.Signer, ks KeySource) ([]ssh.PublicKey, error) {
	keys := map[string]ssh.PublicKey{}

	sk, err := ssh.NewPublicKey(s.Public())
	if err != nil {
		return nil, err
	}
	keys[string(sk.Marshal())] = sk

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

type cacheKeySource struct {
	Wrap     KeySource
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
	curr, err := c.Wrap.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	c.cached = curr
	c.nextFetch = time.Now().Add(c.CacheFor)

	return curr, err
}
