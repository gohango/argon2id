// Package argon2id provides functions to deal with argon2id password protection.
package argon2id

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrPasswordNotMatch    = errors.New("passwords do not match")
)

// params stores the argon2 parameters.
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// decodeHash decodes the argon2 hash and returns the protection parameters.
func decodeHash(hash string) (p *params, salt []byte, hashedPassword []byte, err error) {
	// Example of argon2id hash
	// $argon2id$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM
	// We need to separate the string by $ sign to retrieve:
	// [0] Empty string
	// [1] The algorithm name (argon2id)
	// [2] The version
	// [3] The memory usage, iterations, and parallelism
	// [4] The salt
	// [5] The hashed password

	elems := strings.Split(hash, "$")
	if len(elems) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	// Check the version number.
	var ver int
	_, err = fmt.Sscanf(elems[2], "v=%d", &ver)
	if err != nil {
		return nil, nil, nil, err
	}

	if elems[1] != "argon2id" || ver != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	// Build the parameters.
	p = &params{}
	_, err = fmt.Sscanf(elems[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(elems[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hashedPassword, err = base64.RawStdEncoding.DecodeString(elems[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hashedPassword))

	return p, salt, hashedPassword, nil
}

// CompareHashAndPassword compares a argon2id hashed password with its possible plaintext equivalent.
// Returns nil on success, or an error on failure.
func CompareHashAndPassword(hash string, pass []byte) error {
	p, salt, hashedPass, err := decodeHash(hash)
	if err != nil {
		return err
	}

	// Let's calculate the hash from the user provided password.
	userHash := argon2.IDKey(pass, salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// Let's compare the hash values.
	if subtle.ConstantTimeCompare(userHash, hashedPass) == 0 {
		return ErrPasswordNotMatch
	}

	return nil
}
