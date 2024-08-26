package blackey

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = errors.New("unauthorized: invalid root key")

// CreateAPIKey creates a new API key
func CreateAPIKey(restrictions APIKey) (*APIKey, error) {
	cfg := getConfig()

	// Generate a new API key
	keyBytes := make([]byte, cfg.ByteLength)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	key := cfg.Prefix + base64.URLEncoding.EncodeToString(keyBytes)

	// Hash the root key
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash root key: %w", err)
	}

	// Create a new APIKey instance
	apiKey := &APIKey{
		ID:                 uuid.New().String(),
		Key:                key,
		CreatedAt:          time.Now().UTC(),
		ExpiresAt:          restrictions.ExpiresAt,
		IsActive:           true,
		IsRoot:             false,
		AllowedIPs:         restrictions.AllowedIPs,
		AllowedCountries:   restrictions.AllowedCountries,
		CORSAllowedOrigins: restrictions.CORSAllowedOrigins,
		RateLimit:          restrictions.RateLimit,
		LimitUse:           restrictions.LimitUse,
	}

	// Start a transaction
	tx, err := cfg.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback the transaction if it's not committed

	// Insert the new API key into the database
	_, err = tx.Exec(`
		INSERT INTO _blackey_api_keys (id, key, created_at, expires_at, is_active, is_root, allowed_ips, allowed_countries, cors_allowed_origins, rate_limit, limit_use)
		VALUES ($1, $2, $3, $4, $5, false, $6, $7, $8, $9, $10)
	`, apiKey.ID, hashedKey, apiKey.CreatedAt, apiKey.ExpiresAt, apiKey.IsActive, pq.Array(apiKey.AllowedIPs), pq.Array(apiKey.AllowedCountries), pq.Array(apiKey.CORSAllowedOrigins), apiKey.RateLimit, apiKey.LimitUse)
	if err != nil {
		return nil, fmt.Errorf("failed to insert API key: %w", err)
	}

	// Initialize metrics for the new API key
	metricsID := uuid.New()
	_, err = tx.Exec(`
		INSERT INTO _blackey_metrics (id, api_key_id, success_count, invalid_count, total_access)
		VALUES ($1, $2, 0, 0, 0)
	`, metricsID, apiKey.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return apiKey, nil
}

// Helper function to update API key active status
func updateAPIKeyActiveStatus(keyID string, isActive bool) error {
	cfg := getConfig()

	// Start a transaction
	tx, err := cfg.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback the transaction if it's not committed

	// Update the API key active status
	result, err := tx.Exec(`
		UPDATE _blackey_api_keys
		SET is_active = $1
		WHERE id = $2 AND is_active = $3
	`, isActive, keyID, !isActive)
	if err != nil {
		return fmt.Errorf("failed to update API key active status: %w", err)
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrAPIKeyNotFound
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// RevokeAPIKey revokes an API key
func RevokeAPIKey(keyID string) error {
	return updateAPIKeyActiveStatus(keyID, false)
}

// ActivateAPIKey activates a previously revoked API key
func ActivateAPIKey(keyID string) error {
	return updateAPIKeyActiveStatus(keyID, true)
}

// UpdateAPIKeyRestrictions updates the restrictions for an API key
func UpdateAPIKeyRestrictions(keyID string, restrictions APIKey) error {
	cfg := getConfig()

	// Start a transaction
	tx, err := cfg.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback the transaction if it's not committed

	// Update the API key restrictions
	result, err := tx.Exec(`
		UPDATE _blackey_api_keys
		SET expires_at = COALESCE($1, expires_at),
			allowed_ips = COALESCE($2, allowed_ips),
			allowed_countries = COALESCE($3, allowed_countries),
			cors_allowed_origins = COALESCE($4, cors_allowed_origins),
			rate_limit = COALESCE($5, rate_limit),
			limit_use = COALESCE($6, limit_use)
		WHERE id = $7 AND is_active = true
	`, restrictions.ExpiresAt,
		pq.Array(restrictions.AllowedIPs),
		pq.Array(restrictions.AllowedCountries),
		pq.Array(restrictions.CORSAllowedOrigins),
		restrictions.RateLimit,
		restrictions.LimitUse,
		keyID)

	if err != nil {
		return fmt.Errorf("failed to update API key restrictions: %w", err)
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return ErrAPIKeyNotFound
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// func validateRootKey(db *sql.DB, rootKey string) (bool, error) {
// 	// Validate root key
// 	isRoot, err := IsRootKey(db, rootKey)
// 	if err != nil {
// 		return isRoot, err
// 	}
// 	if !isRoot {
// 		return isRoot, ErrUnauthorized
// 	}

// 	return isRoot, nil
// }
