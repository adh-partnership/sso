package pkce

import (
	"crypto/sha256"
	"encoding/base64"
)

func VerifyCodeVerifierS256(codeChallenge, codeVerifier string) bool {
	hash := sha256.Sum256([]byte(codeVerifier))
	return codeChallenge == base64.RawURLEncoding.EncodeToString(hash[:])
}
