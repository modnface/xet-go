package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	casTokenType         = "XET-CAS"
	casTokenAlgorithm    = "HS256"
	casTokenVersion      = 1
	maximumTokenBytes    = 8 << 10
	maximumHeaderBytes   = 1 << 10
	maximumClaimsBytes   = 4 << 10
	minimumKeyBytes      = 32
	maxCASNamespaceBytes = 2 << 10
	defaultTokenTTL      = 15 * time.Minute
	defaultMaximumTTL    = time.Hour
)

type CASPermissions uint8

const (
	CASRead CASPermissions = 1 << iota
	CASWrite
)

func (permissions CASPermissions) Valid() bool {
	return permissions != 0 && permissions&^(CASRead|CASWrite) == 0
}

func (permissions CASPermissions) Allows(required CASPermissions) bool {
	return required.Valid() && permissions.Valid() && permissions&required == required
}

type CASTokenRequest struct {
	Principal   Principal
	Namespace   string
	Permissions CASPermissions
	// TTL is optional. Zero selects the manager default. Nonzero values must be
	// whole seconds and are bounded by its maximum.
	TTL time.Duration
}

type IssuedCASToken struct {
	Value     string
	ExpiresAt time.Time
	TokenID   string
}

type CASTokenClaims struct {
	Issuer      string
	Subject     string
	Audience    string
	Namespace   string
	Permissions CASPermissions
	IssuedAt    time.Time
	NotBefore   time.Time
	ExpiresAt   time.Time
	TokenID     string
	KeyID       string
}

type CASTokenIssuer interface {
	IssueCASToken(context.Context, CASTokenRequest) (IssuedCASToken, error)
}

type CASTokenVerifier interface {
	VerifyCASToken(context.Context, string) (CASTokenClaims, error)
}

type HMACKey struct {
	ID     string
	Secret []byte
}

type CASTokenManagerOptions struct {
	Issuer           string
	Audience         string
	SigningKey       HMACKey
	VerificationKeys []HMACKey
	DefaultTTL       time.Duration
	MaximumTTL       time.Duration
	ClockSkew        time.Duration
	Now              func() time.Time
	Random           io.Reader
}

// CASTokenManager issues and verifies compact signed credentials. The format
// is intentionally private to xet-go; official Xet clients treat CAS bearer
// credentials as opaque. VerificationKeys enables read-only key rotation.
type CASTokenManager struct {
	issuer, audience string
	signingKeyID     string
	keys             map[string][]byte
	defaultTTL       time.Duration
	maximumTTL       time.Duration
	clockSkew        time.Duration
	now              func() time.Time
	random           io.Reader
}

var (
	_ CASTokenIssuer   = (*CASTokenManager)(nil)
	_ CASTokenVerifier = (*CASTokenManager)(nil)
)

func NewCASTokenManager(options CASTokenManagerOptions) (*CASTokenManager, error) {
	if err := validateASCIIIdentifier("issuer", options.Issuer, maxOpaqueIDBytes); err != nil {
		return nil, err
	}
	if err := validateASCIIIdentifier("audience", options.Audience, maxOpaqueIDBytes); err != nil {
		return nil, err
	}
	if err := validateKey(options.SigningKey); err != nil {
		return nil, err
	}
	if options.DefaultTTL == 0 {
		options.DefaultTTL = defaultTokenTTL
	}
	if options.MaximumTTL == 0 {
		options.MaximumTTL = defaultMaximumTTL
	}
	if options.DefaultTTL < time.Second || options.MaximumTTL < options.DefaultTTL ||
		options.DefaultTTL%time.Second != 0 || options.MaximumTTL%time.Second != 0 {
		return nil, fmt.Errorf("%w: CAS token TTLs must be whole positive seconds and maximum must cover default", ErrInvalid)
	}
	if options.ClockSkew < 0 || options.ClockSkew > 5*time.Minute || options.ClockSkew%time.Second != 0 {
		return nil, fmt.Errorf("%w: CAS token clock skew must be whole seconds from zero through five minutes", ErrInvalid)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	keys := make(map[string][]byte, len(options.VerificationKeys)+1)
	keys[options.SigningKey.ID] = bytes.Clone(options.SigningKey.Secret)
	for _, key := range options.VerificationKeys {
		if err := validateKey(key); err != nil {
			return nil, err
		}
		if _, duplicate := keys[key.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate CAS token key ID", ErrInvalid)
		}
		keys[key.ID] = bytes.Clone(key.Secret)
	}
	return &CASTokenManager{
		issuer: options.Issuer, audience: options.Audience, signingKeyID: options.SigningKey.ID,
		keys: keys, defaultTTL: options.DefaultTTL, maximumTTL: options.MaximumTTL,
		clockSkew: options.ClockSkew, now: options.Now, random: options.Random,
	}, nil
}

type tokenHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Version   int    `json:"v"`
}

type tokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	Namespace string   `json:"ns"`
	Scopes    []string `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	TokenID   string   `json:"jti"`
}

func (manager *CASTokenManager) IssueCASToken(ctx context.Context, request CASTokenRequest) (IssuedCASToken, error) {
	if err := validContext(ctx); err != nil {
		return IssuedCASToken{}, err
	}
	if manager == nil || len(manager.keys) == 0 || manager.now == nil || manager.random == nil {
		return IssuedCASToken{}, fmt.Errorf("%w: CAS token manager is not configured", ErrUnavailable)
	}
	if err := request.Principal.Validate(); err != nil {
		return IssuedCASToken{}, err
	}
	if err := validateOpaqueID("CAS namespace", request.Namespace, maxCASNamespaceBytes); err != nil {
		return IssuedCASToken{}, err
	}
	if !request.Permissions.Valid() {
		return IssuedCASToken{}, fmt.Errorf("%w: invalid CAS permissions", ErrInvalid)
	}
	ttl := manager.defaultTTL
	if request.TTL < 0 {
		return IssuedCASToken{}, fmt.Errorf("%w: negative CAS token TTL", ErrInvalid)
	}
	if request.TTL > 0 {
		if request.TTL%time.Second != 0 || request.TTL > manager.maximumTTL {
			return IssuedCASToken{}, fmt.Errorf("%w: CAS token TTL is invalid or exceeds maximum", ErrInvalid)
		}
		ttl = request.TTL
	}
	if ttl < time.Second || ttl > manager.maximumTTL {
		return IssuedCASToken{}, fmt.Errorf("%w: CAS token TTL is outside configured bounds", ErrInvalid)
	}
	now := manager.now().UTC().Truncate(time.Second)
	if now.IsZero() || now.Unix() <= 0 {
		return IssuedCASToken{}, fmt.Errorf("%w: CAS token clock is invalid", ErrUnavailable)
	}
	tokenIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(manager.random, tokenIDBytes); err != nil {
		return IssuedCASToken{}, fmt.Errorf("%w: generate CAS token identity", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return IssuedCASToken{}, err
	}
	tokenID := base64.RawURLEncoding.EncodeToString(tokenIDBytes)
	expiresAt := now.Add(ttl)
	header := tokenHeader{Type: casTokenType, Algorithm: casTokenAlgorithm, KeyID: manager.signingKeyID, Version: casTokenVersion}
	claims := tokenClaims{
		Issuer: manager.issuer, Subject: request.Principal.Subject, Audience: manager.audience,
		Namespace: request.Namespace, Scopes: permissionScopes(request.Permissions),
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: expiresAt.Unix(), TokenID: tokenID,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return IssuedCASToken{}, fmt.Errorf("%w: encode CAS token header", ErrUnavailable)
	}
	claimBytes, err := json.Marshal(claims)
	if err != nil {
		return IssuedCASToken{}, fmt.Errorf("%w: encode CAS token claims", ErrUnavailable)
	}
	headerPart := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimPart := base64.RawURLEncoding.EncodeToString(claimBytes)
	signed := headerPart + "." + claimPart
	signature := sign([]byte(signed), manager.keys[manager.signingKeyID])
	value := signed + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(value) > maximumTokenBytes {
		return IssuedCASToken{}, fmt.Errorf("%w: encoded CAS token is too large", ErrInvalid)
	}
	return IssuedCASToken{Value: value, ExpiresAt: expiresAt, TokenID: tokenID}, nil
}

func (manager *CASTokenManager) VerifyCASToken(ctx context.Context, value string) (CASTokenClaims, error) {
	if err := validContext(ctx); err != nil {
		return CASTokenClaims{}, err
	}
	if manager == nil || len(manager.keys) == 0 || manager.now == nil {
		return CASTokenClaims{}, fmt.Errorf("%w: CAS token manager is not configured", ErrUnavailable)
	}
	if value == "" || len(value) > maximumTokenBytes {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	var header tokenHeader
	if err := decodeTokenJSON(parts[0], maximumHeaderBytes, &header); err != nil ||
		header.Type != casTokenType || header.Algorithm != casTokenAlgorithm || header.Version != casTokenVersion {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	key, found := manager.keys[header.KeyID]
	if !found {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	signature, err := decodeSegment(parts[2], sha256.Size)
	if err != nil || len(signature) != sha256.Size {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	expected := sign([]byte(parts[0]+"."+parts[1]), key)
	if subtle.ConstantTimeCompare(signature, expected) != 1 {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	var wire tokenClaims
	if err = decodeTokenJSON(parts[1], maximumClaimsBytes, &wire); err != nil {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	claims, err := manager.validateClaims(header.KeyID, wire)
	if err != nil {
		return CASTokenClaims{}, ErrUnauthenticated
	}
	return claims, nil
}

func (manager *CASTokenManager) validateClaims(keyID string, wire tokenClaims) (CASTokenClaims, error) {
	if wire.Issuer != manager.issuer || wire.Audience != manager.audience {
		return CASTokenClaims{}, errors.New("issuer or audience mismatch")
	}
	if err := validateOpaqueID("principal subject", wire.Subject, maxOpaqueIDBytes); err != nil {
		return CASTokenClaims{}, err
	}
	if err := validateOpaqueID("CAS namespace", wire.Namespace, maxCASNamespaceBytes); err != nil {
		return CASTokenClaims{}, err
	}
	permissions, err := parsePermissionScopes(wire.Scopes)
	if err != nil {
		return CASTokenClaims{}, err
	}
	if wire.IssuedAt <= 0 || wire.NotBefore < wire.IssuedAt || wire.ExpiresAt <= wire.NotBefore ||
		wire.ExpiresAt-wire.IssuedAt > int64(manager.maximumTTL/time.Second) {
		return CASTokenClaims{}, errors.New("invalid token lifetime")
	}
	tokenID, err := base64.RawURLEncoding.DecodeString(wire.TokenID)
	if err != nil || len(tokenID) != 16 || base64.RawURLEncoding.EncodeToString(tokenID) != wire.TokenID {
		return CASTokenClaims{}, errors.New("invalid token ID")
	}
	now := manager.now().UTC().Truncate(time.Second)
	skew := int64(manager.clockSkew / time.Second)
	if now.IsZero() || now.Unix()+skew < wire.NotBefore || now.Unix()+skew < wire.IssuedAt || now.Unix()-skew >= wire.ExpiresAt {
		return CASTokenClaims{}, errors.New("token is not currently valid")
	}
	return CASTokenClaims{
		Issuer: wire.Issuer, Subject: wire.Subject, Audience: wire.Audience, Namespace: wire.Namespace,
		Permissions: permissions, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(),
		NotBefore: time.Unix(wire.NotBefore, 0).UTC(), ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC(),
		TokenID: wire.TokenID, KeyID: keyID,
	}, nil
}

func permissionScopes(permissions CASPermissions) []string {
	scopes := make([]string, 0, 2)
	if permissions.Allows(CASRead) {
		scopes = append(scopes, "read")
	}
	if permissions.Allows(CASWrite) {
		scopes = append(scopes, "write")
	}
	return scopes
}

func parsePermissionScopes(scopes []string) (CASPermissions, error) {
	permissions := CASPermissions(0)
	for _, scope := range scopes {
		var permission CASPermissions
		switch scope {
		case "read":
			permission = CASRead
		case "write":
			permission = CASWrite
		default:
			return 0, errors.New("unknown CAS token scope")
		}
		if permissions&permission != 0 {
			return 0, errors.New("duplicate CAS token scope")
		}
		permissions |= permission
	}
	if !permissions.Valid() {
		return 0, errors.New("empty CAS token scope")
	}
	return permissions, nil
}

func validateKey(key HMACKey) error {
	if err := validateKeyID(key.ID); err != nil {
		return err
	}
	if len(key.Secret) < minimumKeyBytes {
		return fmt.Errorf("%w: CAS token HMAC key must contain at least %d bytes", ErrInvalid, minimumKeyBytes)
	}
	return nil
}

func validateKeyID(value string) error {
	if value == "" || len(value) > 64 {
		return fmt.Errorf("%w: invalid CAS token key ID", ErrInvalid)
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' &&
			(character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
			return fmt.Errorf("%w: invalid CAS token key ID", ErrInvalid)
		}
	}
	return nil
}

func validateASCIIIdentifier(name, value string, maximum int) error {
	if value == "" || len(value) > maximum {
		return fmt.Errorf("%w: invalid CAS token %s", ErrInvalid, name)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("%w: invalid CAS token %s", ErrInvalid, name)
		}
	}
	return nil
}

func sign(value, key []byte) []byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	return digest.Sum(nil)
}

func decodeSegment(value string, maximum int) ([]byte, error) {
	if value == "" || len(value) > base64.RawURLEncoding.EncodedLen(maximum) {
		return nil, errors.New("invalid token segment length")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid token segment encoding")
	}
	return decoded, nil
}

func decodeTokenJSON(value string, maximum int, destination any) error {
	raw, err := decodeSegment(value, maximum)
	if err != nil {
		return err
	}
	if err := validateTokenJSONFields(raw, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("multiple token JSON values")
	}
	return nil
}

func validateTokenJSONFields(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("token JSON must be an object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid token JSON field")
		}
		if !allowedTokenJSONField(destination, name) {
			return errors.New("unknown token JSON field")
		}
		if _, duplicate := seen[name]; duplicate {
			return errors.New("duplicate token JSON field")
		}
		seen[name] = struct{}{}
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("invalid token JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing token JSON data")
	}
	return nil
}

func allowedTokenJSONField(destination any, name string) bool {
	switch destination.(type) {
	case *tokenHeader:
		switch name {
		case "typ", "alg", "kid", "v":
			return true
		}
	case *tokenClaims:
		switch name {
		case "iss", "sub", "aud", "ns", "scope", "iat", "nbf", "exp", "jti":
			return true
		}
	}
	return false
}
