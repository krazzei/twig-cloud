package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// tokenBytes is the entropy of every access and refresh token (256 bits).
const tokenBytes = 32

// newToken returns a fresh opaque token: 256 random bits, base64url-encoded
// without padding (43 chars). Only its hashToken digest is ever stored.
func newToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns the hex SHA-256 of a token as presented by the client.
//
// Lookups are done by this digest via the primary-key index rather than by
// comparing secrets in Go. That is timing-safe: an attacker cannot steer the
// digest of a guess, so index timing reveals nothing about stored tokens. A
// fast hash is fine here (unlike passwords) because the input already has
// 256 bits of entropy.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
