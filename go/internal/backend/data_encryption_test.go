package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dsmpass/dsmpass/go/internal/config"
)

func TestPrepareDataSecurityMigratesLegacyInitialPasswordBeforeGeneratingJWTSecret(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(config.BackendConfig{
		AdminAuthEnabled: true,
		AdminUsername:    "owner",
		AdminPassword:    "legacy-admin-hash",
		DataDir:          "/tmp/dsmpass-legacy-test",
	}, testHelper{}, database, queries)

	aead, err := server.legacyInitialPasswordAEAD()
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte("legacy-pass"), []byte("source-a"))
	legacy := base64.RawURLEncoding.EncodeToString(append(nonce, ciphertext...))
	if _, err := database.ExecContext(ctx, `
INSERT INTO source_initial_password_secrets (id, source_slug, encrypted_password)
VALUES ('secret-a', 'source-a', ?)`, legacy); err != nil {
		t.Fatal(err)
	}

	if err := server.PrepareDataSecurity(ctx); err != nil {
		t.Fatal(err)
	}

	var encrypted string
	if err := database.QueryRowContext(ctx, `
SELECT encrypted_password FROM source_initial_password_secrets WHERE source_slug = 'source-a'`).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, initialPasswordVersion) || strings.Contains(encrypted, "legacy-pass") {
		t.Fatalf("legacy initial password was not migrated safely: %q", encrypted)
	}
	password, err := server.decryptInitialPassword("source-a", encrypted)
	if err != nil || password != "legacy-pass" {
		t.Fatalf("migrated password mismatch: %q %v", password, err)
	}

	var storedJWT string
	if err := database.QueryRowContext(ctx, `
SELECT value_json FROM runtime_settings WHERE key = 'admin_jwt_secret'`).Scan(&storedJWT); err != nil {
		t.Fatal(err)
	}
	var jwtSecret string
	if err := json.Unmarshal([]byte(storedJWT), &jwtSecret); err != nil {
		t.Fatal(err)
	}
	if jwtSecret == "" || server.cfg.AdminJWTSecret != jwtSecret {
		t.Fatal("admin JWT secret was not generated after legacy migration")
	}
}

func TestPrepareDataSecurityMigratesLegacyProviderSecret(t *testing.T) {
	ctx := context.Background()
	database, queries, err := OpenDatabase(ctx, "sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	server := NewWithDB(config.BackendConfig{}, testHelper{}, database, queries)
	if _, err := database.ExecContext(ctx, `
INSERT INTO identity_sources (slug, provider_type, display_name, config_json)
VALUES ('source-a', 'feishu', 'Feishu', '{"client_id":"cli_a","client_secret":"legacy-provider-secret"}')`); err != nil {
		t.Fatal(err)
	}

	if err := server.PrepareDataSecurity(ctx); err != nil {
		t.Fatal(err)
	}

	var configJSON string
	if err := database.QueryRowContext(ctx, `
SELECT config_json FROM identity_sources WHERE slug = 'source-a'`).Scan(&configJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(configJSON, "client_secret") || strings.Contains(configJSON, "legacy-provider-secret") {
		t.Fatalf("legacy provider secret remained in config_json: %s", configJSON)
	}
	var encrypted string
	if err := database.QueryRowContext(ctx, `
SELECT encrypted_secret FROM source_client_secrets WHERE source_slug = 'source-a'`).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encrypted, dataEncryptionVersion) || strings.Contains(encrypted, "legacy-provider-secret") {
		t.Fatalf("legacy provider secret was not encrypted independently: %q", encrypted)
	}
	source, err := server.loadIdentitySource(ctx, "source-a")
	if err != nil {
		t.Fatal(err)
	}
	restored := decodeSourceConfigForType(source.ProviderType, source.ConfigJSON)
	if restored.ClientID != "cli_a" || restored.ClientSecret != "legacy-provider-secret" {
		t.Fatalf("migrated provider config mismatch: %#v", restored)
	}
}
