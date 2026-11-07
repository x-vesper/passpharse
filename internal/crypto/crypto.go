package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (RFC 9106 recommended for password hashing).
	argon2Time    = 3         // iterations
	argon2Memory  = 64 * 1024 // 64 MB in KiB
	argon2Threads = 4         // parallelism
	keyLen        = 32        // AES-256
	saltLen       = 16
	nonceLen      = 12 // GCM standard nonce
)

// ErrDecryption indicates the ciphertext or password is invalid.
var ErrDecryption = errors.New("decryption failed: bad password or corrupted data")

// Encrypt encrypts plaintext using password-derived key (argon2id + AES-GCM).
// Returns base64(salt || nonce || ciphertext).
func Encrypt(plaintext, password []byte) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("salt generation: %w", err)
	}

	key := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, keyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	// Seal appends the encrypted data to the output, prepending the nonce.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Output format: salt || nonce || ciphertext
	out := make([]byte, 0, saltLen+len(ciphertext))
	out = append(out, salt...)
	out = append(out, ciphertext...)

	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt. password must match the one used to encrypt.
func Decrypt(b64data string, password []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if len(raw) < saltLen+nonceLen+1 {
		return nil, ErrDecryption
	}

	salt := raw[:saltLen]
	rest := raw[saltLen:]

	nonce := rest[:nonceLen]
	ciphertext := rest[nonceLen:]

	key := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, keyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Authentication failure — wrong password or tampered data.
		return nil, ErrDecryption
	}

	return plaintext, nil
}
