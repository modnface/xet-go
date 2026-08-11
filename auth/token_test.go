package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	casserver "github.com/jmwoliver/xet-go/xetcas/server"
)

func TestCASTokenIssueVerifyAndOperationScope(t *testing.T) {
	now := time.Date(2026, 8, 11, 10, 0, 0, 987654321, time.UTC)
	secret := bytes.Repeat([]byte{0x41}, minimumKeyBytes)
	manager := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "miniface", Audience: "https://cas.example", SigningKey: HMACKey{ID: "current", Secret: secret},
		DefaultTTL: 5 * time.Minute, MaximumTTL: 10 * time.Minute,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x17}, 64)),
	})
	secret[0] ^= 0xff
	issued, err := manager.IssueCASToken(context.Background(), CASTokenRequest{
		Principal: Principal{Subject: "user:alice"}, Namespace: "repo-v1-scope", Permissions: CASRead | CASWrite, TTL: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(issued.Value, ".")) != 3 || issued.TokenID == "" || issued.ExpiresAt != now.Truncate(time.Second).Add(2*time.Minute) {
		t.Fatalf("issued token = %#v", issued)
	}
	claims, err := manager.VerifyCASToken(context.Background(), issued.Value)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user:alice" || claims.Namespace != "repo-v1-scope" || claims.Audience != "https://cas.example" ||
		claims.Issuer != "miniface" || claims.KeyID != "current" || claims.TokenID != issued.TokenID ||
		claims.Permissions != CASRead|CASWrite || claims.IssuedAt != now.Truncate(time.Second) || claims.NotBefore != claims.IssuedAt || claims.ExpiresAt != issued.ExpiresAt {
		t.Fatalf("verified claims = %#v", claims)
	}

	authorizer := CASAuthorizer{Verifier: manager}
	for _, operation := range []casserver.Operation{
		casserver.OperationReadFile, casserver.OperationReadXorb, casserver.OperationReadDedup,
		casserver.OperationWriteXorb, casserver.OperationWriteShard,
	} {
		grant, err := authorizer.Authorize(context.Background(), issued.Value, casserver.AccessRequest{Operation: operation})
		if err != nil || grant.Namespace != claims.Namespace {
			t.Fatalf("operation %q = %#v, %v", operation, grant, err)
		}
	}

	read, err := manager.IssueCASToken(context.Background(), CASTokenRequest{
		Principal: Principal{Subject: "user:alice"}, Namespace: "repo-v1-scope", Permissions: CASRead,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(context.Background(), read.Value, casserver.AccessRequest{Operation: casserver.OperationWriteXorb}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("read token write = %v", err)
	}
	write, err := manager.IssueCASToken(context.Background(), CASTokenRequest{
		Principal: Principal{Subject: "user:alice"}, Namespace: "repo-v1-other", Permissions: CASWrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(context.Background(), write.Value, casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("write token read = %v", err)
	}
	if _, err := authorizer.Authorize(context.Background(), write.Value, casserver.AccessRequest{Operation: casserver.OperationReadXorb}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("write token Xorb read = %v", err)
	}
	grant, err := authorizer.Authorize(context.Background(), write.Value, casserver.AccessRequest{Operation: casserver.OperationReadDedup})
	if err != nil || grant.Namespace != "repo-v1-other" {
		t.Fatalf("write dedup lookup = %#v, %v", grant, err)
	}
	grant, err = authorizer.Authorize(context.Background(), write.Value, casserver.AccessRequest{Operation: casserver.OperationWriteShard})
	if err != nil || grant.Namespace != "repo-v1-other" {
		t.Fatalf("write namespace = %#v, %v", grant, err)
	}
	if _, err := authorizer.Authorize(context.Background(), issued.Value, casserver.AccessRequest{Operation: "future-operation"}); !errors.Is(err, casserver.ErrForbidden) {
		t.Fatalf("unknown operation = %v", err)
	}
	if _, err := authorizer.Authorize(context.Background(), "", casserver.AccessRequest{Operation: casserver.OperationReadFile}); !errors.Is(err, casserver.ErrUnauthorized) {
		t.Fatalf("missing token = %v", err)
	}

	now = issued.ExpiresAt.Add(-time.Second)
	if _, err := manager.VerifyCASToken(context.Background(), issued.Value); err != nil {
		t.Fatalf("token rejected before expiry: %v", err)
	}
	now = issued.ExpiresAt
	if _, err := manager.VerifyCASToken(context.Background(), issued.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("token accepted at expiry: %v", err)
	}
	wrongAudience := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "miniface", Audience: "https://other-cas.example", SigningKey: HMACKey{ID: "current", Secret: bytes.Repeat([]byte{0x41}, minimumKeyBytes)},
	})
	if _, err := wrongAudience.VerifyCASToken(context.Background(), issued.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("wrong audience = %v", err)
	}
}

func TestCASTokenKeyRotationAndClockSkew(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	oldSecret := bytes.Repeat([]byte{1}, minimumKeyBytes)
	oldKey := HMACKey{ID: "old", Secret: oldSecret}
	newKey := HMACKey{ID: "new", Secret: bytes.Repeat([]byte{2}, minimumKeyBytes)}
	old := testTokenManager(t, &now, CASTokenManagerOptions{Issuer: "issuer", Audience: "cas", SigningKey: oldKey})
	oldToken, err := old.IssueCASToken(context.Background(), validTokenRequest())
	if err != nil {
		t.Fatal(err)
	}
	rotated := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "issuer", Audience: "cas", SigningKey: newKey, VerificationKeys: []HMACKey{oldKey}, ClockSkew: 2 * time.Second,
	})
	oldSecret[0] ^= 0xff
	if claims, err := rotated.VerifyCASToken(context.Background(), oldToken.Value); err != nil || claims.KeyID != "old" {
		t.Fatalf("rotated old token = %#v, %v", claims, err)
	}
	newToken, err := rotated.IssueCASToken(context.Background(), validTokenRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.VerifyCASToken(context.Background(), newToken.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old verifier accepted new key = %v", err)
	}
	newOnly := testTokenManager(t, &now, CASTokenManagerOptions{Issuer: "issuer", Audience: "cas", SigningKey: newKey})
	if _, err := newOnly.VerifyCASToken(context.Background(), oldToken.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("retired key accepted = %v", err)
	}
	now = oldToken.ExpiresAt.Add(time.Second)
	if _, err := rotated.VerifyCASToken(context.Background(), oldToken.Value); err != nil {
		t.Fatalf("skew did not cover expiry: %v", err)
	}
	now = oldToken.ExpiresAt.Add(2 * time.Second)
	if _, err := rotated.VerifyCASToken(context.Background(), oldToken.Value); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("token accepted at skew boundary = %v", err)
	}
}

func TestCASTokenConfigurationAndIssuanceErrors(t *testing.T) {
	key := HMACKey{ID: "key", Secret: bytes.Repeat([]byte{3}, minimumKeyBytes)}
	valid := CASTokenManagerOptions{Issuer: "issuer", Audience: "cas", SigningKey: key}
	for name, mutate := range map[string]func(*CASTokenManagerOptions){
		"issuer":      func(options *CASTokenManagerOptions) { options.Issuer = "" },
		"audience":    func(options *CASTokenManagerOptions) { options.Audience = "bad audience" },
		"key ID":      func(options *CASTokenManagerOptions) { options.SigningKey.ID = "bad/key" },
		"short key":   func(options *CASTokenManagerOptions) { options.SigningKey.Secret = []byte("short") },
		"long key ID": func(options *CASTokenManagerOptions) { options.SigningKey.ID = strings.Repeat("k", 65) },
		"default TTL": func(options *CASTokenManagerOptions) { options.DefaultTTL = 500 * time.Millisecond },
		"maximum TTL": func(options *CASTokenManagerOptions) {
			options.DefaultTTL, options.MaximumTTL = time.Minute, 30*time.Second
		},
		"fractional TTL": func(options *CASTokenManagerOptions) { options.DefaultTTL = time.Second + time.Millisecond },
		"negative skew":  func(options *CASTokenManagerOptions) { options.ClockSkew = -time.Second },
		"large skew":     func(options *CASTokenManagerOptions) { options.ClockSkew = 6 * time.Minute },
		"duplicate key":  func(options *CASTokenManagerOptions) { options.VerificationKeys = []HMACKey{key} },
		"invalid verification key": func(options *CASTokenManagerOptions) {
			options.VerificationKeys = []HMACKey{{ID: "old", Secret: []byte("short")}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			options.SigningKey.Secret = bytes.Clone(valid.SigningKey.Secret)
			mutate(&options)
			if _, err := NewCASTokenManager(options); !errors.Is(err, ErrInvalid) {
				t.Fatalf("configuration = %v", err)
			}
		})
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	manager := testTokenManager(t, &now, valid)
	if _, err := manager.IssueCASToken(context.Background(), CASTokenRequest{
		Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: CASRead, TTL: defaultMaximumTTL,
	}); err != nil {
		t.Fatalf("maximum TTL rejected: %v", err)
	}
	for name, request := range map[string]CASTokenRequest{
		"principal":      {Principal: Principal{}, Namespace: "scope", Permissions: CASRead},
		"namespace":      {Principal: Principal{Subject: "user"}, Namespace: "", Permissions: CASRead},
		"permission":     {Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: 8},
		"negative TTL":   {Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: CASRead, TTL: -time.Second},
		"fractional TTL": {Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: CASRead, TTL: time.Second + time.Millisecond},
		"large TTL":      {Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: CASRead, TTL: defaultMaximumTTL + time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := manager.IssueCASToken(context.Background(), request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("issuance = %v", err)
			}
		})
	}
	badRandom := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "issuer", Audience: "cas", SigningKey: key, Random: errorReader{},
	})
	if _, err := badRandom.IssueCASToken(context.Background(), validTokenRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("random failure = %v", err)
	}
	cancelContext, cancelAfterRandom := context.WithCancel(context.Background())
	canceling := testTokenManager(t, &now, CASTokenManagerOptions{
		Issuer: "issuer", Audience: "cas", SigningKey: key, Random: cancelingReader{cancel: cancelAfterRandom},
	})
	if _, err := canceling.IssueCASToken(cancelContext, validTokenRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after randomness = %v", err)
	}
	invalidClock := time.Time{}
	badClock := testTokenManager(t, &invalidClock, valid)
	if _, err := badClock.IssueCASToken(context.Background(), validTokenRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("clock failure = %v", err)
	}
	var nilManager *CASTokenManager
	if _, err := nilManager.IssueCASToken(context.Background(), validTokenRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil issuer = %v", err)
	}
	if _, err := nilManager.VerifyCASToken(context.Background(), "token"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil verifier = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.IssueCASToken(canceled, validTokenRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled issue = %v", err)
	}
	if _, err := manager.VerifyCASToken(canceled, "token"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled verify = %v", err)
	}
}

func TestCASTokenRejectsMalformedAndInvalidClaims(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := HMACKey{ID: "key", Secret: bytes.Repeat([]byte{4}, minimumKeyBytes)}
	manager := testTokenManager(t, &now, CASTokenManagerOptions{Issuer: "issuer", Audience: "cas", SigningKey: key})
	validWire := tokenClaims{
		Issuer: "issuer", Subject: "user", Audience: "cas", Namespace: "scope", Scopes: []string{"read"},
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		TokenID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 16)),
	}
	header := tokenHeader{Type: casTokenType, Algorithm: casTokenAlgorithm, KeyID: key.ID, Version: casTokenVersion}
	valid := makeSignedToken(t, header, validWire, key.Secret)
	parts := strings.Split(valid, ".")
	malformed := []string{
		"", "one", "one.two", "one.two.three.four", strings.Repeat("x", maximumTokenBytes+1),
		"%%%." + parts[1] + "." + parts[2],
		parts[0] + ".%%% ." + parts[2],
		parts[0] + "." + parts[1] + ".%%%,",
		parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-1] + "A",
	}
	for _, value := range malformed {
		if _, err := manager.VerifyCASToken(context.Background(), value); !errors.Is(err, ErrUnauthenticated) || strings.Contains(err.Error(), value) && value != "" {
			t.Fatalf("malformed token %q = %v", value, err)
		}
	}
	for _, rawClaims := range [][]byte{[]byte(`[]`), []byte(`{`), []byte(`{"iss":`), []byte(`{"iss":"issuer"`)} {
		value := makeSignedRawToken(t, header, rawClaims, key.Secret)
		if _, err := manager.VerifyCASToken(context.Background(), value); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("malformed signed claims %q = %v", rawClaims, err)
		}
	}
	for name, badHeader := range map[string]any{
		"type":          tokenHeader{Type: "other", Algorithm: casTokenAlgorithm, KeyID: key.ID, Version: casTokenVersion},
		"algorithm":     tokenHeader{Type: casTokenType, Algorithm: "none", KeyID: key.ID, Version: casTokenVersion},
		"key":           tokenHeader{Type: casTokenType, Algorithm: casTokenAlgorithm, KeyID: "unknown", Version: casTokenVersion},
		"version":       tokenHeader{Type: casTokenType, Algorithm: casTokenAlgorithm, KeyID: key.ID, Version: 2},
		"unknown field": map[string]any{"typ": casTokenType, "alg": casTokenAlgorithm, "kid": key.ID, "v": 1, "extra": true},
		"case folded":   map[string]any{"typ": casTokenType, "ALG": casTokenAlgorithm, "kid": key.ID, "v": 1},
	} {
		t.Run("header "+name, func(t *testing.T) {
			if _, err := manager.VerifyCASToken(context.Background(), makeSignedToken(t, badHeader, validWire, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("header accepted = %v", err)
			}
		})
	}
	mutations := map[string]func(*tokenClaims){
		"issuer":          func(claims *tokenClaims) { claims.Issuer = "other" },
		"audience":        func(claims *tokenClaims) { claims.Audience = "other" },
		"subject":         func(claims *tokenClaims) { claims.Subject = "" },
		"namespace":       func(claims *tokenClaims) { claims.Namespace = " bad" },
		"empty scope":     func(claims *tokenClaims) { claims.Scopes = nil },
		"unknown scope":   func(claims *tokenClaims) { claims.Scopes = []string{"admin"} },
		"duplicate scope": func(claims *tokenClaims) { claims.Scopes = []string{"read", "read"} },
		"issued zero":     func(claims *tokenClaims) { claims.IssuedAt = 0 },
		"early nbf":       func(claims *tokenClaims) { claims.NotBefore-- },
		"empty lifetime":  func(claims *tokenClaims) { claims.ExpiresAt = claims.NotBefore },
		"long lifetime":   func(claims *tokenClaims) { claims.ExpiresAt = claims.IssuedAt + int64(2*time.Hour/time.Second) },
		"future":          func(claims *tokenClaims) { claims.IssuedAt += 10; claims.NotBefore += 10; claims.ExpiresAt += 10 },
		"expired":         func(claims *tokenClaims) { claims.ExpiresAt = now.Unix() },
		"token ID":        func(claims *tokenClaims) { claims.TokenID = "bad" },
	}
	for name, mutate := range mutations {
		t.Run("claims "+name, func(t *testing.T) {
			claims := validWire
			claims.Scopes = append([]string(nil), validWire.Scopes...)
			mutate(&claims)
			if _, err := manager.VerifyCASToken(context.Background(), makeSignedToken(t, header, claims, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("claims accepted = %v", err)
			}
		})
	}
	unknownClaims := map[string]any{
		"iss": "issuer", "sub": "user", "aud": "cas", "ns": "scope", "scope": []string{"read"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": validWire.TokenID, "extra": true,
	}
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedToken(t, header, unknownClaims, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("unknown claim = %v", err)
	}
	caseFoldedClaims := map[string]any{
		"ISS": "issuer", "sub": "user", "aud": "cas", "ns": "scope", "SCOPE": []string{"read"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": validWire.TokenID,
	}
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedToken(t, header, caseFoldedClaims, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("case-folded claims = %v", err)
	}
	semanticDuplicateClaims := map[string]any{
		"iss": "issuer", "ISS": "issuer", "sub": "user", "aud": "cas", "ns": "scope", "scope": []string{"read"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": validWire.TokenID,
	}
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedToken(t, header, semanticDuplicateClaims, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("semantic duplicate claims = %v", err)
	}
	duplicateClaims := fmt.Sprintf(
		`{"iss":"issuer","iss":"issuer","sub":"user","aud":"cas","ns":"scope","scope":["read"],"iat":%d,"nbf":%d,"exp":%d,"jti":"%s"}`,
		now.Unix(), now.Unix(), now.Add(time.Minute).Unix(), validWire.TokenID,
	)
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedRawToken(t, header, []byte(duplicateClaims), key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("duplicate claim = %v", err)
	}
	duplicateHeader := []byte(`{"typ":"XET-CAS","alg":"HS256","alg":"HS256","kid":"key","v":1}`)
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedRawParts(t, duplicateHeader, mustJSON(t, validWire), key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("duplicate header = %v", err)
	}
	trailingClaims := append(mustJSON(t, validWire), []byte(` {}`)...)
	if _, err := manager.VerifyCASToken(context.Background(), makeSignedRawToken(t, header, trailingClaims, key.Secret)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("trailing claims = %v", err)
	}
}

func FuzzCASTokenVerify(f *testing.F) {
	now := time.Unix(2_000_000_000, 0).UTC()
	manager, err := NewCASTokenManager(CASTokenManagerOptions{
		Issuer: "issuer", Audience: "cas", SigningKey: HMACKey{ID: "key", Secret: bytes.Repeat([]byte{7}, minimumKeyBytes)},
		Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{8}, 64)),
	})
	if err != nil {
		f.Fatal(err)
	}
	issued, err := manager.IssueCASToken(context.Background(), validTokenRequest())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", ".", "a.b.c", issued.Value, strings.Repeat("x", maximumTokenBytes+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		claims, err := manager.VerifyCASToken(context.Background(), value)
		if err == nil && (!claims.Permissions.Valid() || claims.Namespace == "" || claims.Subject == "") {
			t.Fatalf("invalid successful claims: %#v", claims)
		}
	})
}

func testTokenManager(t *testing.T, now *time.Time, options CASTokenManagerOptions) *CASTokenManager {
	t.Helper()
	if options.Now == nil {
		options.Now = func() time.Time { return *now }
	}
	if options.Random == nil {
		options.Random = bytes.NewReader(bytes.Repeat([]byte{0x23}, 256))
	}
	manager, err := NewCASTokenManager(options)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func validTokenRequest() CASTokenRequest {
	return CASTokenRequest{Principal: Principal{Subject: "user"}, Namespace: "scope", Permissions: CASRead}
}

func makeSignedToken(t *testing.T, header, claims any, key []byte) string {
	t.Helper()
	return makeSignedRawToken(t, header, mustJSON(t, claims), key)
}

func makeSignedRawToken(t *testing.T, header any, claimBytes, key []byte) string {
	t.Helper()
	return makeSignedRawParts(t, mustJSON(t, header), claimBytes, key)
}

func makeSignedRawParts(t *testing.T, headerBytes, claimBytes, key []byte) string {
	t.Helper()
	headerPart := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimPart := base64.RawURLEncoding.EncodeToString(claimBytes)
	signed := headerPart + "." + claimPart
	return signed + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(signed), key))
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type cancelingReader struct{ cancel context.CancelFunc }

func (reader cancelingReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = byte(index)
	}
	reader.cancel()
	return len(destination), nil
}
