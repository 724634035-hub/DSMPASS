package backend

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

const (
	dataEncryptionKeySize = 32
	dataEncryptionVersion = "v1:"
)

// LoadOrCreateDataEncryptionKey returns a persistent 32-byte key encoded as
// base64url. The key is intentionally independent from the admin JWT secret so
// that a database or backup leak does not expose the key needed to decrypt
// stored secrets.
func LoadOrCreateDataEncryptionKey(cfg config.BackendConfig) (string, error) {
	if raw := strings.TrimSpace(cfg.DataEncryptionKey); raw != "" {
		key, err := decodeDataEncryptionKey(raw)
		if err != nil {
			return "", fmt.Errorf("DSMPASS_DATA_ENCRYPTION_KEY: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(key), nil
	}

	path := strings.TrimSpace(cfg.DataEncryptionKeyFile)
	if path == "" {
		return "", errors.New("data encryption key file is not configured")
	}
	key, err := readDataEncryptionKeyFile(path)
	if err == nil {
		return base64.RawURLEncoding.EncodeToString(key), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create data encryption key directory: %w", err)
	}
	key = make([]byte, dataEncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate data encryption key: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		key, err = readDataEncryptionKeyFile(path)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(key), nil
	}
	if err != nil {
		return "", fmt.Errorf("create data encryption key file: %w", err)
	}
	if _, err := io.WriteString(file, encoded+"\n"); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write data encryption key file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync data encryption key file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close data encryption key file: %w", err)
	}
	return encoded, nil
}

func readDataEncryptionKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat data encryption key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("data encryption key path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure data encryption key permissions: %w", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read data encryption key file: %w", err)
	}
	key, err := decodeDataEncryptionKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("data encryption key file: %w", err)
	}
	return key, nil
}

func decodeDataEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("key is empty")
	}
	if len(raw) == dataEncryptionKeySize*2 {
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == dataEncryptionKeySize {
			return decoded, nil
		}
	}
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil && len(decoded) == dataEncryptionKeySize {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("key must encode exactly %d bytes as base64url or hex", dataEncryptionKeySize)
}

func serverDataEncryptionKey(raw string) ([]byte, error) {
	if strings.TrimSpace(raw) != "" {
		return decodeDataEncryptionKey(raw)
	}
	key := make([]byte, dataEncryptionKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ephemeral data encryption key: %w", err)
	}
	return key, nil
}

func (s *Server) PrepareDataSecurity(ctx context.Context) error {
	if s.store == nil {
		return errors.New("database store is not configured")
	}
	if s.dataEncryptionKeyErr != nil {
		return s.dataEncryptionKeyErr
	}
	if len(s.dataEncryptionKey) != dataEncryptionKeySize {
		return errors.New("data encryption key is not initialized")
	}
	if err := s.migrateLegacySourceClientSecrets(ctx); err != nil {
		return fmt.Errorf("migrate identity source client secrets: %w", err)
	}
	if err := s.migrateLegacyInitialPasswords(ctx); err != nil {
		return fmt.Errorf("migrate source initial passwords: %w", err)
	}
	if err := s.ensureAdminJWTSecret(ctx); err != nil {
		return fmt.Errorf("prepare admin JWT secret: %w", err)
	}
	return nil
}

func (s *Server) dataAEAD(purpose string) (cipher.AEAD, error) {
	if s.dataEncryptionKeyErr != nil {
		return nil, s.dataEncryptionKeyErr
	}
	if len(s.dataEncryptionKey) != dataEncryptionKeySize {
		return nil, errors.New("data encryption key is not initialized")
	}
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return nil, errors.New("data encryption purpose is required")
	}
	material := make([]byte, 0, len(s.dataEncryptionKey)+len(purpose)+32)
	material = append(material, []byte("dsmpass-data-encryption-v1\x00")...)
	material = append(material, s.dataEncryptionKey...)
	material = append(material, 0)
	material = append(material, purpose...)
	key := sha256.Sum256(material)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Server) sealData(purpose string, plaintext []byte) (string, error) {
	aead, err := s.dataAEAD(purpose)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(purpose))
	payload := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (s *Server) openData(purpose, encoded string) ([]byte, error) {
	aead, err := s.dataAEAD(purpose)
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(payload) <= nonceSize {
		return nil, errors.New("invalid encrypted data")
	}
	return aead.Open(nil, payload[:nonceSize], payload[nonceSize:], []byte(purpose))
}

func (s *Server) encryptDataSecret(purpose, plaintext string) (string, error) {
	payload, err := s.sealData(purpose, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return dataEncryptionVersion + payload, nil
}

func (s *Server) decryptDataSecret(purpose, encrypted string) (string, error) {
	if !strings.HasPrefix(encrypted, dataEncryptionVersion) {
		return "", errors.New("unsupported encrypted data version")
	}
	payload, err := s.openData(purpose, strings.TrimPrefix(encrypted, dataEncryptionVersion))
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
