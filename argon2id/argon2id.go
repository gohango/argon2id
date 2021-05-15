// Package argon2id provides functions to deal with argon2id password protection.
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrPasswordNotMatch    = errors.New("passwords do not match")
)

// Params stores the argon2 parameters.
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// decodeHash decodes the argon2 hash and returns the protection parameters.
func decodeHash(hash string) (p *Params, salt []byte, hashedPassword []byte, err error) {
	// Example of argon2id hash
	// $argon2id$v=19$m=4096,t=3,p=1$82XldKYgqAqher7EuFzPNw$O1Epnr+m1JYkgtWcgVLID39ro6He105HTFnE+SinJyM
	// We need to separate the string by $ sign to retrieve:
	// [0] Empty string
	// [1] The algorithm name (argon2id)
	// [2] The version
	// [3] The Memory usage, Iterations, and Parallelism
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
	p = &Params{}
	_, err = fmt.Sscanf(elems[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(elems[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hashedPassword, err = base64.RawStdEncoding.DecodeString(elems[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hashedPassword))

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
	userHash := argon2.IDKey(pass, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Let's compare the hash values.
	if subtle.ConstantTimeCompare(userHash, hashedPass) == 0 {
		return ErrPasswordNotMatch
	}

	return nil
}

// GenerateFromPassword generates the string representation of argon2id from the given password and parameters.
// Returns the string representation with nil error when successful. On failure, it returns empty string with non-nil error.
func GenerateFromPassword(pass []byte, p *Params) (string, error) {
	if p == nil {
		// We will use default configuration here.
		p = &Params{
			Memory:      4096,
			Iterations:  10,
			Parallelism: 2,
			SaltLength:  32,
			KeyLength:   64,
		}
	}

	// Generate the salt.
	unencodedSalt := make([]byte, p.SaltLength)

	_, err := io.ReadFull(rand.Reader, unencodedSalt)
	if err != nil {
		return "", err
	}

	// Generate the hashed password.
	hash := argon2.IDKey(pass, unencodedSalt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Generate the string representation.
	encodedSalt := base64.RawStdEncoding.EncodeToString(unencodedSalt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, encodedSalt, encodedHash), nil
}
