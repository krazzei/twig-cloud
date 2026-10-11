package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: RFC 9106 §4, second recommended option (the
// "memory-constrained" profile). Roughly 50-100 ms per hash on a modern core.
//
// Changing these only affects new hashes: the parameters are encoded into
// every stored hash, and VerifyPassword reads them back from there.
const (
	argon2Time    = 3         // passes over memory
	argon2Memory  = 64 * 1024 // KiB, i.e. 64 MiB
	argon2Threads = 4
	argon2SaltLen = 16 // bytes
	argon2KeyLen  = 32 // bytes
)

// ErrMalformedHash means a stored password hash could not be parsed. It
// indicates corrupt data, not a wrong password.
var ErrMalformedHash = errors.New("auth: malformed password hash")

var b64 = base64.RawStdEncoding

// HashPassword returns an argon2id hash of password in the PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>
func HashPassword(password string) string {
	salt := make([]byte, argon2SaltLen)
	_, _ = rand.Read(salt) // crypto/rand.Read never returns an error (Go 1.24+)
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// VerifyPassword reports whether password matches encoded, a hash produced by
// HashPassword. The comparison is constant-time. A non-nil error means the
// hash itself is unusable (ErrMalformedHash), never a mismatch.
func VerifyPassword(encoded, password string) (bool, error) {
	p, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

type argon2Hash struct {
	time, memory uint32
	threads      uint8
	salt, key    []byte
}

func parseHash(encoded string) (argon2Hash, error) {
	var h argon2Hash
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return h, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return h, ErrMalformedHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.time, &h.threads); err != nil {
		return h, ErrMalformedHash
	}
	if h.memory == 0 || h.time == 0 || h.threads == 0 {
		return h, ErrMalformedHash
	}
	var err error
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) == 0 {
		return h, ErrMalformedHash
	}
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) == 0 {
		return h, ErrMalformedHash
	}
	return h, nil
}
