package backend

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dsmpass/dsmpass/go/internal/db"
)

const sourceClientSecretPurposePrefix = "source-client-secret:"

func sourceClientSecretPurpose(sourceSlug string) string {
	return sourceClientSecretPurposePrefix + strings.TrimSpace(sourceSlug)
}

func (s *Server) loadSourceClientSecret(ctx context.Context, sourceSlug string) (string, bool, error) {
	var encrypted string
	err := s.store.DBTX().QueryRowContext(ctx, `
SELECT encrypted_secret
FROM source_client_secrets
WHERE source_slug = ?`, strings.TrimSpace(sourceSlug)).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) || isMissingSourceClientSecretTable(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	secret, err := s.decryptDataSecret(sourceClientSecretPurpose(sourceSlug), encrypted)
	if err != nil {
		return "", false, fmt.Errorf("decrypt client secret for %s: %w", sourceSlug, err)
	}
	return secret, true, nil
}

func (s *Server) saveSourceClientSecret(ctx context.Context, q db.DBTX, sourceSlug, secret string) error {
	sourceSlug = strings.TrimSpace(sourceSlug)
	secret = strings.TrimSpace(secret)
	if sourceSlug == "" || secret == "" {
		return nil
	}
	encrypted, err := s.encryptDataSecret(sourceClientSecretPurpose(sourceSlug), secret)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, `
INSERT INTO source_client_secrets (source_slug, encrypted_secret, created_at, updated_at)
VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(source_slug) DO UPDATE SET
    encrypted_secret = excluded.encrypted_secret,
    updated_at = CURRENT_TIMESTAMP
`, sourceSlug, encrypted)
	return err
}

func (s *Server) deleteSourceClientSecret(ctx context.Context, q db.DBTX, sourceSlug string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM source_client_secrets WHERE source_slug = ?`, strings.TrimSpace(sourceSlug))
	return err
}

func (s *Server) hydrateSourceClientSecret(ctx context.Context, source *db.IdentitySource) error {
	if source == nil || strings.TrimSpace(source.Slug) == "" {
		return nil
	}
	secret, ok, err := s.loadSourceClientSecret(ctx, source.Slug)
	if err != nil || !ok {
		return err
	}
	config := decodeSourceConfigForType(source.ProviderType, source.ConfigJSON)
	config.ClientSecret = secret
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	source.ConfigJSON = string(raw)
	return nil
}

func isMissingSourceClientSecretTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table: source_client_secrets")
}

func (s *Server) migrateLegacySourceClientSecrets(ctx context.Context) error {
	rows, err := s.store.DBTX().QueryContext(ctx, `SELECT slug, provider_type, config_json FROM identity_sources`)
	if err != nil {
		return err
	}
	type legacySecret struct {
		slug     string
		secret   string
		configJS string
	}
	var migrations []legacySecret
	for rows.Next() {
		var slug, providerType, raw string
		if err := rows.Scan(&slug, &providerType, &raw); err != nil {
			rows.Close()
			return err
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &document); err != nil {
			rows.Close()
			return fmt.Errorf("identity source %s has invalid config_json: %w", slug, err)
		}
		rawSecret, ok := document["client_secret"]
		if !ok {
			continue
		}
		var secret string
		if err := json.Unmarshal(rawSecret, &secret); err != nil {
			rows.Close()
			return fmt.Errorf("identity source %s has invalid client_secret: %w", slug, err)
		}
		delete(document, "client_secret")
		encoded, err := json.Marshal(document)
		if err != nil {
			rows.Close()
			return err
		}
		migrations = append(migrations, legacySecret{
			slug:     slug,
			secret:   strings.TrimSpace(secret),
			configJS: string(encoded),
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, migration := range migrations {
		if migration.secret != "" {
			if err := s.saveSourceClientSecret(ctx, s.store.DBTX(), migration.slug, migration.secret); err != nil {
				return fmt.Errorf("store client secret for %s: %w", migration.slug, err)
			}
		}
		if _, err := s.store.DBTX().ExecContext(ctx, `
UPDATE identity_sources
SET config_json = ?, updated_at = CURRENT_TIMESTAMP
WHERE slug = ?`, migration.configJS, migration.slug); err != nil {
			return fmt.Errorf("remove plaintext client secret for %s: %w", migration.slug, err)
		}
	}
	return nil
}
