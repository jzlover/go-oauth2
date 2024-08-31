package generates

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jzlover/go-oauth2"
	"github.com/jzlover/go-oauth2/errors"
)

type (
	GenerateAuthoritiesHandler func(data *oauth2.GenerateBasic) ([]string, error)

	GenerateClaimsHandler func(data *oauth2.GenerateBasic) (jwt.Claims, error)
)

type JWTAccessClaimsExt struct {
	JWTAccessClaims
}

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	jwt.StandardClaims
	Authorities []string `json:"authorities,omitempty"`
	Sign        string   `json:"sign,omitempty"`
	ClientId    string   `json:"cid,omitempty"`
	Username    string   `json:"user_name,omitempty"`
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(kid string, key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod

	generateAuthoritiesHandler GenerateAuthoritiesHandler
	generateClaimsHandler      GenerateClaimsHandler
}

func (a *JWTAccessGenerate) SetGenerateAuthoritiesHandler(handler GenerateAuthoritiesHandler) {
	a.generateAuthoritiesHandler = handler
}

func (a *JWTAccessGenerate) SetGenerateClaimsHandler(handler GenerateClaimsHandler) {
	a.generateClaimsHandler = handler
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {

	var authorities []string
	var err error
	if a.generateAuthoritiesHandler != nil {
		if authorities, err = a.generateAuthoritiesHandler(data); err != nil {
			return "", "", err
		}
	}

	var claims jwt.Claims
	if a.generateClaimsHandler != nil {
		claims, err = a.generateClaimsHandler(data)
		if err != nil {
			return "", "", err
		}
	} else {
		claims = &JWTAccessClaims{
			StandardClaims: jwt.StandardClaims{
				Audience:  data.Client.GetID(),
				Subject:   data.UserID,
				ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
			},
			Authorities: authorities,
			Sign:        data.TokenInfo.GetSign(),
			ClientId:    data.Client.GetID(),
			Username:    data.UserID,
		}
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", "", err
		}
		key = v
	} else {
		return "", "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	refresh := ""

	if isGenRefresh {
		t := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
		refresh = base64.URLEncoding.EncodeToString([]byte(t))
		refresh = strings.ToUpper(strings.TrimRight(refresh, "="))
	}

	return access, refresh, nil
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}

func (a *JWTAccessGenerate) isEd() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "Ed")
}
