package argon2_test

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"github.com/rackorbit/argon2"
)

func TestMain(m *testing.M) {
	initDataset()

	os.Exit(m.Run())
}

func TestHash(t *testing.T) {
	if dataset == nil {
		panic("test dataset is empty")
	}

	if numberOfPasswords != len(dataset) {
		t.Fatalf("dataset failed to generate")
		return
	}

	for i, password := range dataset {
		password, err := argon2.Hash([]byte(password))
		if err != nil {
			t.Errorf("Test #%d: Should not have error return value, but received \"%v\"", i, err)
			continue
		}

		if password == nil {
			t.Errorf("Test #%d: Expected non-nil value, but got one", i)
			continue
		}

		hashes = append(hashes, password)
	}

	if numberOfPasswords != len(hashes) {
		t.Fatalf("hashset failed to generate")
		return
	}
}

var _hash []byte

func BenchmarkHash(b *testing.B) {
	numberOfPasswords = b.N

	initDataset()

	if dataset == nil {
		panic("test dataset is empty")
	}

	b.Run("Hash", func(b *testing.B) {
		var h []byte

		for i := 0; i < b.N; i++ {
			h, _ = argon2.Hash([]byte(dataset[i]))
		}

		_hash = h
	})
}

func TestVerify(t *testing.T) {
	if dataset == nil {
		panic("test dataset is empty")
	}

	t.Run("With Valid Password", func(t *testing.T) {
		for i, password := range dataset {
			if err := argon2.Verify([]byte(password), hashes[i]); err != nil {
				t.Errorf("Test #%d: Should not have error return value, but received \"%v\"", i, err)
				continue
			}
		}
	})

	t.Run("With Invalid Password", func(t *testing.T) {
		for i, password := range dataset {
			if err := argon2.Verify([]byte(password[:len(password)-1]), hashes[i]); err != argon2.ErrFailedVerify {
				t.Errorf("Test #%d: Should've received ErrFailedVerify, but received \"%v\"", i, err)
				continue
			}
		}
	})
}

// ---------------------------------- \\

const (
	lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits           = "0123456789"
	symbols          = "~!@#$%^&*()-={}|[]\\:\"<>?,./"
)

var numberOfPasswords = 10

var (
	dataset []string
	hashes  [][]byte
)

func initDataset() {
	if dataset != nil {
		return
	}

	for i := 0; i < numberOfPasswords; i++ {
		p, err := generatePassword(96, 8, 12)
		if err != nil {
			panic(err)
			return
		}

		dataset = append(dataset, p)
	}
}

func generatePassword(length, numDigits, numSymbols int) (string, error) {
	letters := lowercaseLetters + uppercaseLetters
	chars := length - numDigits - numSymbols

	var result string

	// Characters
	for i := 0; i < chars; i++ {
		ch, err := randomElement(letters)
		if err != nil {
			return "", err
		}

		result, err = randomInsert(result, ch)
		if err != nil {
			return "", err
		}
	}

	// Digits
	for i := 0; i < numDigits; i++ {
		d, err := randomElement(digits)
		if err != nil {
			return "", err
		}

		result, err = randomInsert(result, d)
		if err != nil {
			return "", err
		}
	}

	// Symbols
	for i := 0; i < numSymbols; i++ {
		sym, err := randomElement(symbols)
		if err != nil {
			return "", err
		}

		result, err = randomInsert(result, sym)
		if err != nil {
			return "", err
		}
	}

	return result, nil
}

// randomInsert randomly inserts the given value into the given string.
func randomInsert(s, val string) (string, error) {
	if s == "" {
		return val, nil
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s)+1)))
	if err != nil {
		return "", err
	}

	i := n.Int64()
	return s[0:i] + val + s[i:], nil
}

// randomElement extracts a random element from the given string.
func randomElement(s string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return "", err
	}

	return string(s[n.Int64()]), nil
}
