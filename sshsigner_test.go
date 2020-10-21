package sshsigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	pseudorand "math/rand"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lstoll/grpce/inproc"
	"github.com/pardot/oidc"
	sshsigner "github.com/pardot/sshsigner/proto/sshsigner/v1alpha1"
	"github.com/pkg/errors"
	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"
)

func TestSSHSigner(t *testing.T) {
	ctx := context.Background()

	hostSigner := newMockSigner(t)
	userSigner := newMockSigner(t)
	nonceRec := &mockNonceRecorder{}

	signer, err := New(
		logrus.New(),
		userSigner,
		hostSigner,
		nonceRec,
		&fakeVerifier{},
		"aud",
		[]string{},
	)
	if err != nil {
		t.Fatal(err)
	}

	isvr := inproc.New()
	sshsigner.RegisterSignerServer(isvr.Server, signer)

	if err := isvr.Start(); err != nil {
		t.Fatal(err)
	}
	defer isvr.Close()

	scli := sshsigner.NewSignerClient(isvr.ClientConn)

	t.Run("Serving user keyset", func(t *testing.T) {
		resp, err := scli.UserSigners(context.Background(), &empty.Empty{})
		if err != nil {
			t.Fatalf("Error fetching user signers: %v", err)
		}
		if len(resp.VerificationKeys) != 2 {
			t.Errorf("want 2 verification key, got %d", len(resp.VerificationKeys))
		}

		wantCKeys, err := userSigner.PublicKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}

		var (
			wantKeys []string
			gotKeys  []string
		)

		for _, pk := range wantCKeys {
			sk, err := ssh.NewPublicKey(pk)
			if err != nil {
				t.Fatal(err)
			}
			wantKeys = append(wantKeys, string(ssh.MarshalAuthorizedKey(sk)))
		}

		for _, vk := range resp.VerificationKeys {
			gotKeys = append(gotKeys, string(vk.Key))
		}

		if diff := cmp.Diff(wantKeys, gotKeys, cmpopts.SortSlices(func(x, y string) bool { return strings.Compare(x, y) < 0 })); diff != "" {
			t.Errorf("Unexpected keys returned: %s", diff)
		}
	})

	t.Run("Serving host keyset", func(t *testing.T) {
		resp, err := scli.HostSigners(context.Background(), &empty.Empty{})
		if err != nil {
			t.Fatalf("Error fetching host signers: %v", err)
		}
		if len(resp.VerificationKeys) != 2 {
			t.Errorf("want 2 verification key, got %d", len(resp.VerificationKeys))
		}

		wantCKeys, err := hostSigner.PublicKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}

		var (
			wantKeys []string
			gotKeys  []string
		)

		for _, pk := range wantCKeys {
			sk, err := ssh.NewPublicKey(pk)
			if err != nil {
				t.Fatal(err)
			}
			wantKeys = append(wantKeys, string(ssh.MarshalAuthorizedKey(sk)))
		}

		for _, vk := range resp.VerificationKeys {
			gotKeys = append(gotKeys, string(vk.Key))
		}

		if diff := cmp.Diff(wantKeys, gotKeys, cmpopts.SortSlices(func(x, y string) bool { return strings.Compare(x, y) < 0 })); diff != "" {
			t.Errorf("Unexpected keys returned: %s", diff)
		}
	})
}

func TestSSHSigner_SignUserKey(t *testing.T) {
	now := time.Now().Round(time.Second) // certs only have second granularity

	fakePublicKey, err := ssh.NewPublicKey(&rsa.PublicKey{N: big.NewInt(4), E: 65537})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name            string
		playedNonces    []string
		req             *sshsigner.SignUserKeyRequest
		claims          *oidc.Claims
		wantErr         string
		wantPrincipals  []string
		wantValidBefore time.Time
		opts            []SignerOpt
	}{
		{
			name: "Valid",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				Expiry:  oidc.NewUnixTime(now.Add(15 * time.Minute)),
				ACR:     ACRMultiFactorPhysical,
				AMR:     []string{AMROTP},
				Nonce:   "nonce123",
				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantErr: "",
			wantPrincipals: []string{
				"group:ops",
				"group:developers",
				fmt.Sprintf("acr:%s", ACRMultiFactorPhysical),
				fmt.Sprintf("amr:%s", AMROTP),
			},
			wantValidBefore: now.Add(15 * time.Minute),
		},
		{
			name: "Valid, expiry less than max",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				Expiry:  oidc.NewUnixTime(now.Add(10 * time.Minute)),
				Nonce:   "nonce123",
				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantErr: "",
			wantPrincipals: []string{
				"group:ops",
				"group:developers",
			},
			wantValidBefore: now.Add(10 * time.Minute),
		},
		{
			name: "Not a user",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Extra: map[string]interface{}{
					"awsInstance": true,
				},
			},
			wantErr: "only users may use this RPC",
		},
		{
			name: "Not a valid SSH key",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: "bogus",
			},
			claims: &oidc.Claims{
				Subject: "subject",
				ACR:     ACRMultiFactorPhysical,
				AMR:     []string{AMROTP},
				Nonce:   "nonce123",

				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantErr: "failed to sign user key",
		},
		{
			name: "Token has empty list of groups",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				ACR:     ACRMultiFactorPhysical,
				AMR:     []string{AMROTP},
				Nonce:   "nonce123",

				Extra: map[string]interface{}{
					"groups": []interface{}{},
				},
			},
			wantErr: "user must be member of at least one group",
		},
		{
			name: "Empty nonce",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				ACR:     ACRMultiFactorPhysical,
				AMR:     []string{AMROTP},

				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantErr: "empty nonce",
		},
		{
			name:         "Replayed nonce",
			playedNonces: []string{"nonce123"},
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				ACR:     ACRMultiFactorPhysical,
				AMR:     []string{AMROTP},
				Nonce:   "nonce123",

				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantErr: "invalid nonce",
		},
		{
			name: "Custom validity",
			req: &sshsigner.SignUserKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
			},
			claims: &oidc.Claims{
				Subject: "subject",
				// longer than we expect, should be forced down to max
				Expiry: oidc.NewUnixTime(now.Add(120 * time.Minute)),
				ACR:    ACRMultiFactorPhysical,
				AMR:    []string{AMROTP},
				Nonce:  "nonce123",
				Extra: map[string]interface{}{
					"groups": []interface{}{"ops", "developers"},
				},
			},
			wantPrincipals: []string{
				"group:ops",
				"group:developers",
				fmt.Sprintf("acr:%s", ACRMultiFactorPhysical),
				fmt.Sprintf("amr:%s", AMROTP),
			},
			wantErr:         "",
			wantValidBefore: now.Add(60 * time.Minute),
			opts:            []SignerOpt{WithMaxUserCertValidityPeriod(1 * time.Hour)},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			validToken := "abc123"
			verifier := &fakeVerifier{
				tokens: map[string]*oidc.Claims{
					validToken: tc.claims,
				},
			}

			hostSigner := newMockSigner(t)
			userSigner := newMockSigner(t)
			nonceRec := &mockNonceRecorder{nonces: tc.playedNonces}

			signer, err := New(
				logrus.New(),
				userSigner,
				hostSigner,
				nonceRec,
				verifier,
				"aud",
				[]string{},
				tc.opts...,
			)
			if err != nil {
				t.Fatal(err)
			}
			signer.clock = func() time.Time { return now }

			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.New(map[string]string{"authorization": "bearer " + validToken}),
			)

			resp, err := signer.SignUserKey(ctx, tc.req)
			if (tc.wantErr != "" && err == nil) || (tc.wantErr == "" && err != nil) {
				t.Fatalf("wantErr: %v, err: %v", tc.wantErr, err)
			} else if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("wantErr: %v, err: %v", tc.wantErr, err)
			}

			if tc.wantErr == "" {
				akey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.SignedCertificate))
				if err != nil {
					t.Fatal(err)
				}

				cert, ok := akey.(*ssh.Certificate)
				if !ok {
					t.Fatalf("wanted a %T, got a %T", &ssh.Certificate{}, cert)
				}

				if !reflect.DeepEqual(tc.wantPrincipals, cert.ValidPrincipals) {
					t.Errorf("wanted principals %v, got %v", tc.wantPrincipals, cert.ValidPrincipals)
				}

				fmt.Printf("%#v\n", cert)
				if !tc.wantValidBefore.IsZero() && !tc.wantValidBefore.Equal(time.Unix(int64(cert.ValidBefore), 0)) {
					t.Errorf("wanted valid before %v, got %v", tc.wantValidBefore, time.Unix(int64(cert.ValidBefore), 0))
				}
			}
		})
	}
}

func TestSSHSigner_SignHostKey(t *testing.T) {
	now := time.Now().Round(time.Second) // certs only have second granularity

	hostSigner := newMockSigner(t)
	userSigner := newMockSigner(t)

	fakePublicKey, err := ssh.NewPublicKey(&rsa.PublicKey{N: big.NewInt(4), E: 65537})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name             string
		req              *sshsigner.SignHostKeyRequest
		claims           *oidc.Claims
		validAWSAccounts []string
		playedNonces     []string
		wantErr          string
		wantValidBefore  time.Time
		opts             []SignerOpt
	}{
		{
			name: "Valid",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::1234567:assumed-role/aws:ec2-instance/i-1234567",
				},
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "",
		},
		{
			name: "Not an EC2 instance",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::1234567:assumed-role/foo/i-1234567",
				},
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "invalid ARN",
		},
		{
			name: "Not an AWS token",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce:   "abc",
				Subject: "subj",
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "only AWS roles may use this RPC",
		},
		{
			name: "Missing hostnames",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: nil,
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::1234567:assumed-role/aws:ec2-instance/i-1234567",
				},
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "at least one hostname must be specified",
		},
		{
			name: "Invalid AWS account",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::987654:assumed-role/aws:ec2-instance/i-1234567",
				},
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "invalid ARN",
		},
		{
			name: "Dupe nonce",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::1234567:assumed-role/aws:ec2-instance/i-1234567",
				},
			},
			playedNonces:     []string{"abc"},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "invalid nonce",
		},
		{
			name: "Custom Expiry",
			req: &sshsigner.SignHostKeyRequest{
				PublicKey: string(ssh.MarshalAuthorizedKey(fakePublicKey)),
				Hostnames: []string{"instance.example.com"},
			},
			claims: &oidc.Claims{
				Nonce: "abc",
				Extra: map[string]interface{}{
					"awsInstance": true,
					"arn":         "arn:aws:sts::1234567:assumed-role/aws:ec2-instance/i-1234567",
				},
			},
			validAWSAccounts: []string{"1234567"},
			wantErr:          "",
			wantValidBefore:  now.Add(7 * 24 * time.Hour),
			opts:             []SignerOpt{WithHostCertValidityPeriod(7 * 24 * time.Hour)},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			validToken := "abc123"
			verifier := &fakeVerifier{
				tokens: map[string]*oidc.Claims{
					validToken: tc.claims,
				},
			}

			nonceRec := &mockNonceRecorder{nonces: tc.playedNonces}

			signer, err := New(
				logrus.New(),
				userSigner,
				hostSigner,
				nonceRec,
				verifier,
				"aud",
				tc.validAWSAccounts,
				tc.opts...,
			)
			if err != nil {
				t.Fatal(err)
			}
			signer.clock = func() time.Time { return now }

			ctx := metadata.NewIncomingContext(
				context.Background(),
				metadata.New(map[string]string{"authorization": "bearer " + validToken}),
			)

			resp, err := signer.SignHostKey(ctx, tc.req)
			if (tc.wantErr != "" && err == nil) || (tc.wantErr == "" && err != nil) {
				t.Fatalf("wantErr: %v, err: %v", tc.wantErr, err)
			} else if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("wantErr: %v, err: %v", tc.wantErr, err)
			}

			if tc.wantErr == "" {
				akey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.SignedCertificate))
				if err != nil {
					t.Fatal(err)
				}

				cert, ok := akey.(*ssh.Certificate)
				if !ok {
					t.Fatalf("wanted a %T, got a %T", &ssh.Certificate{}, cert)
				}

				if !tc.wantValidBefore.IsZero() && !tc.wantValidBefore.Equal(time.Unix(int64(cert.ValidBefore), 0)) {
					t.Errorf("wanted valid before %v, got %v", tc.wantValidBefore, time.Unix(int64(cert.ValidBefore), 0))
				}
			}

		})
	}
}

func TestAuth(t *testing.T) {
	l, _ := test.NewNullLogger()

	aud := "audience"

	fv := &fakeVerifier{
		tokens: map[string]*oidc.Claims{
			"good": &oidc.Claims{
				Subject:  "good",
				Audience: []string{aud},
			},
			"badaud": &oidc.Claims{
				Subject:  "good",
				Audience: []string{"bad"},
			},
		},
	}

	for _, tc := range []struct {
		name       string
		authHeader string
		wantErr    bool
	}{
		{
			name:       "Valid",
			authHeader: "Bearer good",
			wantErr:    false,
		},
		{
			name:       "Empty header",
			authHeader: "",
			wantErr:    true,
		},
		{
			name:       "Invalid token",
			authHeader: "Bearer abcdef",
			wantErr:    true,
		},
		{
			name:       "Not bearer token",
			authHeader: "Basic good",
			wantErr:    true,
		},
		{
			name:       "Invalid format",
			authHeader: "Bogus abcdef",
			wantErr:    true,
		},
		{
			name:       "Invalid format 2",
			authHeader: "Bogus",
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &SSHSigner{
				Log:      l,
				Verifier: fv,
				Audience: aud,
			}

			md := metadata.MD{}
			if tc.authHeader != "" {
				md["authorization"] = []string{tc.authHeader}
			}

			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := s.authRequest(ctx)
			if (err == nil && tc.wantErr) || (err != nil && !tc.wantErr) {
				t.Errorf("want err %v, got err = %v", tc.wantErr, err)
			}
		})
	}
}

func TestSigner(t *testing.T) {
	// just grab the crypto.signer to use here
	signerSrc := newMockSigner(t)
	signer, err := signerSrc.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	capub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}

	testKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZ8p94l0BrORNBO8vXKzz0xtnvKCSNj0Gu7Fhzi9OutYGFkdfDNVs3WxU19eP6ec7dsYJOBLdWuIUWd2eTfaQg8VLCFlG+w6bvKgc0BK/C6bBnwLtBkyE9wq1Fwl6cOJrRvLJgelf30BuXt9gsDBhXmCLS60Lw1lvQKoGaLOkiJFs9cDP7/mxLABg6nnUyHaDnWkI1VfTlENbuq/oFhhWFbrAq1Us3JODdaExXG7wlIz19nxnGOGIrQjZEMiPRo9ao1KkYR1jpISVI/0UZEZ4VCW7AlLVtJIqiW1/FaMT5wul3XUVRF/wqlmIFCwhpbbJMl1rQS52rQkylBbz+rlUF lstoll@lstoll-ltm.bna.lds.li"

	cases := []struct {
		description string
		req         sshCertReq
		expErr      bool
	}{
		{"test with an invalid key", sshCertReq{ssh.UserCert, []byte("invalid key"), "test", []string{"root", "admin"}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, true},
		{"test with valid key and principals", sshCertReq{ssh.UserCert, []byte(testKey), "testid", []string{"admin", "root"}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, false},
		{"test with valid key and reversed principals", sshCertReq{ssh.UserCert, []byte(testKey), "testid", []string{"root", "admin"}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, false},
		{"test with an empty key", sshCertReq{ssh.UserCert, []byte(""), "testid", []string{"root", "admin"}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, true},
		{"test with an empty id", sshCertReq{ssh.UserCert, []byte(testKey), "", []string{"root", "admin"}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, true},
		{"test with no principals", sshCertReq{ssh.UserCert, []byte(testKey), "testid", []string{}, ssh.Permissions{}, time.Now(), time.Now().Add(15 * time.Minute)}, true},
	}

	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			cert, err := signRequest(signer, tc.req)
			if tc.expErr {
				if err == nil {
					t.Error("want error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("want no error, got: %v", err)
				}
			}

			if err != nil {
				return
			}

			parsedCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
			if err != nil {
				t.Fatal(err)
			}
			sshCert := parsedCert.(*ssh.Certificate)

			if len(sshCert.SignatureKey.Marshal()) < 1 || !bytes.Equal(sshCert.SignatureKey.Marshal(), capub.Marshal()) {
				t.Error("Cert was not signed by our CA")
			}

			cc := ssh.CertChecker{}
			if err := cc.CheckCert(tc.req.Principals[0], sshCert); err != nil {
				t.Errorf("Failed checking cert: %v", err)
			}

			// ignore CA verification errors
			_ = capub.Verify(sshCert.Marshal(), sshCert.Signature)

			sort.Strings(tc.req.Principals)
			sort.Strings(sshCert.ValidPrincipals)

			if tc.req.ID != sshCert.KeyId {
				t.Errorf("want key ID %s, got %s", tc.req.ID, sshCert.KeyId)
			}

			if tc.req.ID != sshCert.KeyId {
				t.Errorf("want key ID %s, got %s", tc.req.ID, sshCert.KeyId)
			}

			if !reflect.DeepEqual(tc.req.Principals, sshCert.ValidPrincipals) {
				t.Errorf("Want principals %v, got %v", tc.req.Principals, sshCert.ValidPrincipals)
			}
		})
	}
}

type fakeVerifier struct {
	tokens map[string]*oidc.Claims
}

func (f *fakeVerifier) VerifyRaw(ctx context.Context, audience string, raw string, opts ...oidc.VerifyOpt) (*oidc.Claims, error) {
	t, ok := f.tokens[raw]
	if !ok {
		return nil, errors.New("invalid token")
	}
	return t, nil
}

func newMockSigner(t *testing.T) *mockSignerSource {
	var err error

	s, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	v, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}

	return &mockSignerSource{
		signer:  s,
		addlKey: v.Public(),
	}
}

type mockSignerSource struct {
	signer      crypto.Signer
	addlKey     crypto.PublicKey
	pubkeyCalls int64
}

func (s *mockSignerSource) Signer(context.Context) (crypto.Signer, error) {
	return s.signer, nil
}

func (s *mockSignerSource) PublicKeys(context.Context) ([]crypto.PublicKey, error) {
	atomic.AddInt64(&s.pubkeyCalls, 1)
	return []crypto.PublicKey{s.signer.Public(), s.addlKey}, nil
}

type mockNonceRecorder struct {
	nonces []string
}

// RecordNonce should note that a given nonce was used, and indicate if it was
func (m *mockNonceRecorder) RecordNonce(ctx context.Context, nonce string, _ time.Time) (used bool, err error) {
	for _, n := range m.nonces {
		if nonce == n {
			return true, nil
		}
	}

	m.nonces = append(m.nonces, nonce)

	return false, nil
}

func TestCache(t *testing.T) {
	ctx := context.Background()

	ks := newMockSigner(t)

	cache := &cacheKeySource{
		SignerSource: ks,
		CacheFor:     1 * time.Minute,
	}

	var wg sync.WaitGroup
	var errs []error

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.PublicKeys(ctx)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}

	if ks.pubkeyCalls != 1 {
		t.Errorf("want ks called once, got: %d", ks.pubkeyCalls)
	}

	// now try a bunch of concurrent fetches
	cache.CacheFor = -1 * time.Minute
	cache.nextFetch = time.Now().Add(cache.CacheFor)
	ks.pubkeyCalls = 0

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.PublicKeys(ctx)
			if err != nil {
				errs = append(errs, err)
			}
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}

	if ks.pubkeyCalls != 10 {
		t.Errorf("want ks called 10 times, got: %d", ks.pubkeyCalls)
	}
}

func TestCacheControl(t *testing.T) {
	s := &SSHSigner{
		remoteCacheFor:   5 * time.Minute,
		remoteCacheSplay: 1 * time.Minute,
		rand:             pseudorand.New(pseudorand.NewSource(0)),
	}

	md := s.cacheControlMD()

	cc := md.Get("cache-control")
	if len(cc) != 1 {
		t.Fatalf("want 1 Cache-Control header, got: %d", len(cc))
	}

	reqDir, err := cacheobject.ParseRequestCacheControl(cc[0])
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("reqDir: %#v", reqDir)

	// constant seed == constant splay
	if reqDir.MaxAge != 312 {
		t.Errorf("wanted 312s max age, got: %d", reqDir.MaxAge)
	}
}
