package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 64 * 1024 // 64 MiB
	argonTime    = 2
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var usernameRegex = regexp.MustCompile(`^[a-z0-9._-]{3,30}$`)

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash)

	return encoded, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid password hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("incompatible argon2 version")
	}

	var memory, iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false, errors.New("invalid argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1, nil
}

func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return errors.New("Password minimal 8 karakter")
	}
	if len(password) > 128 {
		return errors.New("Password maksimal 128 karakter")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("Password harus mengandung huruf besar, huruf kecil, angka, dan simbol")
	}
	return nil
}

func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 150 {
		return "", errors.New("Format email tidak valid")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", errors.New("Format email tidak valid")
	}
	return email, nil
}

func NormalizeUsername(raw string) (string, error) {
	username := strings.ToLower(strings.TrimSpace(raw))
	if !usernameRegex.MatchString(username) {
		return "", errors.New("Username harus 3-30 karakter (huruf, angka, titik, garis bawah, atau strip)")
	}
	return username, nil
}

func NormalizeName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if len(name) < 2 || len(name) > 100 {
		return "", errors.New("Nama lengkap harus antara 2 hingga 100 karakter")
	}
	return name, nil
}

func GenerateRandomToken(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashTokenSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func ComputeBodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func ComputeHMACSignature(secret, method, path, timestamp, nonce, bodyHash string) string {
	payload := strings.Join([]string{strings.ToUpper(method), path, timestamp, nonce, bodyHash}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyHMACSignature(secret, method, path, timestamp, nonce, bodyHash, signature string) bool {
	expected := ComputeHMACSignature(secret, method, path, timestamp, nonce, bodyHash)
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}
	return hmac.Equal(sigBytes, expectedBytes)
}

func ParseTimestampValid(tsHeader string, maxSkew time.Duration) bool {
	unixSec, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	reqTime := time.Unix(unixSec, 0)
	diff := time.Since(reqTime)
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxSkew
}

// NonceStore tracks recent gateway nonces to defeat replay attacks.
type NonceStore struct {
	mu    sync.Mutex
	items map[string]time.Time
	ttl   time.Duration
}

func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		items: make(map[string]time.Time),
		ttl:   ttl,
	}
}

func (s *NonceStore) CheckAndStore(nonce string) bool {
	if len(nonce) < 16 {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.items) > 10000 {
		for k, exp := range s.items {
			if now.After(exp) {
				delete(s.items, k)
			}
		}
	}

	if exp, exists := s.items[nonce]; exists && now.Before(exp) {
		return false
	}
	s.items[nonce] = now.Add(s.ttl)
	return true
}
