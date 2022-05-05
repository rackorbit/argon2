// Package argon2 provides an easy-to-use wrapper around the argon2 crypto
// library.
package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

const (
	Version = argon2.Version

	Memory      uint32 = 65536
	Iterations  uint32 = 3
	Parallelism uint8  = 2
	SaltLength  uint32 = 16
	KeyLength   uint32 = 32
)

var (
	// ErrIncompatibleVersion is an incompatible version error.
	ErrIncompatibleVersion = errors.New("argon2: incompatible version")

	// ErrInvalidHash is an invalid hash error.
	ErrInvalidHash = errors.New("argon2: invalid hash")

	// ErrFailedVerify is a failed verification error.
	ErrFailedVerify = errors.New("argon2: failed verify")
)

// Hash hashes the input using the argon2id algorithm.
func Hash(input []byte) ([]byte, error) {
	salt, err := generateRandomBytes(SaltLength)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	key, err := idKey(input, salt)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.WriteString("$argon2id$v=")
	b.WriteString(strconv.FormatInt(Version, 10))
	b.WriteString("$m=")
	b.WriteString(strconv.FormatUint(uint64(Memory), 10))
	b.WriteString(",t=")
	b.WriteString(strconv.FormatUint(uint64(Iterations), 10))
	b.WriteString(",p=")
	b.WriteString(strconv.FormatUint(uint64(Parallelism), 10))
	b.WriteByte('$')
	b.Write(encodeBase64(salt))
	b.WriteByte('$')
	b.Write(encodeBase64(key))
	return b.Bytes(), nil
}

// Verify verifies the input against a hash.
func Verify(input, hash []byte) error {
	salt, hash, err := decodeHash(hash)
	if err != nil {
		return err
	}

	comparisonHash, err := idKey(input, salt)
	if err != nil {
		return err
	}

	// Compare the two hashes. Using subtle#ConstantTimeCompare is
	// important for security as using bytes#Equal would make this
	// vulnerable to timing attacks, which would not be good.
	if subtle.ConstantTimeCompare(hash, comparisonHash) != 1 {
		return ErrFailedVerify
	}
	return nil
}

// HashAndVerify hashes the input using the argon2id algorithm, then verifies it.
func HashAndVerify(input []byte) ([]byte, error) {
	hashed, err := Hash(input)
	if err != nil {
		return nil, err
	}

	// Verify the input against the generated hash. This ensures that the hashed
	// password is valid and works with the input it was derived from.
	if err := Verify(input, hashed); err != nil {
		return nil, ErrFailedVerify
	}
	return hashed, nil
}

// idKey gets the argon2 id key.
func idKey(input, salt []byte) ([]byte, error) {
	return argon2.IDKey(input, salt, Iterations, Memory, Parallelism, KeyLength), nil
}

// decodeHash decodes the argon2 hash from a string.
func decodeHash(encodedHash []byte) ([]byte, []byte, error) {
	values := bytes.Split(encodedHash, []byte{'$'})
	if len(values) != 6 {
		return nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Fscanf(bytes.NewReader(values[2]), "v=%d", &version); err != nil {
		return nil, nil, err
	}
	if version != Version {
		return nil, nil, ErrIncompatibleVersion
	}

	salt, err := decodeBase64(values[4])
	if err != nil {
		return nil, nil, fmt.Errorf("argon2: failed to decode base64: %v", err)
	}
	hash, err := decodeBase64(values[5])
	if err != nil {
		return nil, nil, fmt.Errorf("argon2: failed to decode base64: %v", err)
	}
	return salt, hash, nil
}

// encodeBase64 encodes a byte slice using base64.
func encodeBase64(src []byte) []byte {
	buf := make([]byte, base64.RawStdEncoding.EncodedLen(len(src)))
	base64.RawStdEncoding.Encode(buf, src)
	return buf
}

// decodeBase64 decodes a base64 string.
func decodeBase64(src []byte) ([]byte, error) {
	buf := make([]byte, base64.RawStdEncoding.DecodedLen(len(src)))
	n, err := base64.RawStdEncoding.Decode(buf, src)
	return buf[:n], err
}

// generateRandomBytes generates crypto-secure random bytes.
func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("argon2: failed to gen random: %v", err)
	}
	return b, nil
}

// Password .
type Password []byte

// Set .
func (p *Password) Set(password []byte) error {
	if password == nil {
		return nil
	}
	h, err := HashAndVerify(password)
	if err != nil {
		return err
	}
	*p = h
	return nil
}

// Verify .
func (p Password) Verify(input []byte) (bool, error) {
	if input == nil {
		return false, nil
	}
	if err := Verify(input, p); err != nil {
		return false, err
	}
	return true, nil
}

// MarshalJSON satisfies the json.Marshaler interface.
func (Password) MarshalJSON() ([]byte, error) {
	return nil, nil
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (Password) UnmarshalJSON([]byte) error {
	return nil
}
