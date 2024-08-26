package blackey

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Config represents the configuration for the blackey module
type Config struct {
	DB         *sql.DB
	Prefix     string
	ByteLength int
}

var (
	config     *Config
	configOnce sync.Once
)

// Init initializes the blackey module with the provided configuration
func Init(cfg Config) error {
	var err error
	configOnce.Do(func() {
		if cfg.ByteLength == 0 {
			cfg.ByteLength = 16 // Default byte length
		}
		if cfg.DB == nil {
			err = errors.New("blackey: no database provided")
			return
		}
		config = &cfg
		err = SetupTables(cfg.DB)
	})
	return err
}

// getConfig returns the initialized configuration
func getConfig() *Config {
	if config == nil {
		panic("blackey: module not initialized")
	}
	return config
}

// APIKey represents an API key in the system
type APIKey struct {
	ID                 string
	Key                string
	CreatedAt          time.Time
	ExpiresAt          *time.Time
	IsActive           bool
	IsRoot             bool
	AllowedIPs         []string
	AllowedCountries   []string
	CORSAllowedOrigins []string
	RateLimit          *int
	LimitUse           *int
}

// ActivityLog represents a log entry for API key usage
type ActivityLog struct {
	ID        string
	APIKeyID  string
	Timestamp time.Time
	UserAgent string
	IPAddress string
	Region    string
}

// Metrics represents usage metrics for an API key
type Metrics struct {
	APIKeyID      string
	ExpiresAt     *time.Time
	RemainingUses *int
	LastUsage     time.Time
	SuccessCount  int
	InvalidCount  int
	TotalAccess   int
}

var (
	ErrAPIKeyNotFound         = errors.New("API key not found")
	ErrInvalidAPIKey          = errors.New("invalid API key")
	ErrExpiredAPIKey          = errors.New("expired API key")
	ErrLimitUsageExceeded     = errors.New("API key limit usage exceeded")
	ErrRateLimitExceeded      = errors.New("rate limit exceeded")
	ErrInsufficientPrivileges = errors.New("insufficient privileges")
	ErrInvalidAPIKeyID        = errors.New("invalid API key ID format")
	ErrMissingAPIKeyOrID      = errors.New("missing api key or id")
	ErrInternalServerError    = errors.New("internal server error")
	ErrIPNotAllowed           = errors.New("ip not allowed")
	ErrFailedToVerifyRootKey  = errors.New("failed to verify root key")
)

// Initialize sets up the necessary tables and generates a root key if not already initialized
func Initialize(db *sql.DB, prefix string, byteLength int) error {
	// Call Init to initialize the configuration
	err := Init(Config{DB: db, Prefix: prefix, ByteLength: byteLength})
	if err != nil {
		return fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// Check if already initialized
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM _blackey_api_keys WHERE is_root = true").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check initialization status: %w", err)
	}

	if count > 0 {
		fmt.Println("blackey is already initialized")
		return nil
	}

	// Generate root key
	keyBytes := make([]byte, byteLength)
	_, err = rand.Read(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}
	rootKey := prefix + base64.URLEncoding.EncodeToString(keyBytes)

	// Hash the root key
	hashedKey, err := bcrypt.GenerateFromPassword([]byte(rootKey), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash root key: %w", err)
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert root key
	rootKeyID := uuid.New()
	_, err = tx.Exec(`
		INSERT INTO _blackey_api_keys (id, key, is_root, is_active, created_at)
		VALUES ($1, $2, true, true, $3)
	`, rootKeyID, hashedKey, time.Now())
	if err != nil {
		return fmt.Errorf("failed to insert root key: %w", err)
	}

	// Initialize metrics for root key
	metricsID := uuid.New()
	_, err = tx.Exec(`
		INSERT INTO _blackey_metrics (id, api_key_id, success_count, invalid_count, total_access)
		VALUES ($1, $2, 0, 0, 0)
	`, metricsID, rootKeyID)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics for root key: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fmt.Printf("Blackey initialized successfully. Root ID %s and Key %s \n", rootKeyID, rootKey)
	fmt.Println("IMPORTANT: Store this root key securely. It will not be shown again. You can check it on the database if needed.")

	return nil
}
