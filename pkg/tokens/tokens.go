package tokens

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var JWKS string
var KeySet jwk.Set

var (
	ErrNoKeys = fmt.Errorf("no keys available")
)

func BuildKeyset(jwks string) error {
	var err error
	JWKS = jwks
	KeySet, err = jwk.Parse([]byte(JWKS))
	if err != nil {
		return err
	}
	return nil
}

func GetRandomKey() (jwk.Key, bool) {
	return KeySet.Key(rand.Intn(KeySet.Len()))
}

// Kubernetes' OIDC client only supports RS256 signed keys
// so make sure we only get those
func GetRandomKubernetesKey() (jwk.Key, bool) {
	var key jwk.Key
	var b bool
	for key.Algorithm() != jwa.RS256 {
		key, b = GetRandomKey()
	}

	return key, b
}

func CreateTokenKubernetes(issuer, audience, subject string, ttl int, claims map[string]interface{}) ([]byte, error) {
	key, ok := GetRandomKubernetesKey()
	if !ok {
		return nil, ErrNoKeys
	}

	return createTokenFromKey(key, issuer, audience, subject, ttl, claims)
}

func CreateToken(issuer, audience, subject string, ttl int, claims map[string]interface{}) ([]byte, error) {
	key, ok := GetRandomKey()
	if !ok {
		return nil, ErrNoKeys
	}

	return createTokenFromKey(key, issuer, audience, subject, ttl, claims)
}

func createTokenFromKey(key jwk.Key, issuer, audience, subject string, ttl int, claims map[string]interface{}) ([]byte, error) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.AudienceKey, audience)
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Duration(ttl)*time.Second).Unix())
	for k, v := range claims {
		token.Set(k, v)
	}

	return jwt.Sign(token, jwt.WithKey(key.Algorithm(), key))
}
