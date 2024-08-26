package blackey

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/tomasen/realip"
	"golang.org/x/crypto/bcrypt"
)

type ErrorResponse func(w http.ResponseWriter, message string, statusCode int)

type MiddlewareConfig struct {
	APIIDHeaderName  string
	APIKeyHeaderName string
	HeaderPrefix     string
	ErrorHandler     ErrorResponse
}

func defaultErrorHandler(w http.ResponseWriter, message string, statusCode int) {
	http.Error(w, message, statusCode)
}

var limiter *RateLimiter

func init() {
	limiter = NewRateLimiter()
}

func ValidateAPIKey(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle CORS preflight requests
			if r.Method == "OPTIONS" {
				handleCORS(w, r, nil, cfg)
				return
			}

			// Extract API key from header
			apiKey, apiKeyID := extractAPIKey(r, cfg)
			if _, err := uuid.Parse(apiKeyID); err != nil {
				cfg.ErrorHandler(w, ErrInvalidAPIKeyID.Error(), http.StatusBadRequest)
				return
			}
			if apiKey == "" || apiKeyID == "" {
				cfg.ErrorHandler(w, ErrMissingAPIKeyOrID.Error(), http.StatusUnauthorized)
				return
			}

			// Validate API key
			keyDetails, err := validateKey(apiKeyID, apiKey)

			// Handle CORS for non-preflight requests
			handleCORS(w, r, keyDetails, cfg)

			if err != nil {
				status := http.StatusInternalServerError
				message := fmt.Sprintf("%v: %v", ErrInternalServerError.Error(), err)
				if errors.Is(err, ErrInvalidAPIKey) {
					status = http.StatusUnauthorized
					message = ErrInvalidAPIKey.Error()
				} else if errors.Is(err, ErrAPIKeyNotFound) {
					status = http.StatusNotFound
					message = ErrAPIKeyNotFound.Error()
				} else if errors.Is(err, ErrExpiredAPIKey) {
					status = http.StatusUnauthorized
					message = ErrExpiredAPIKey.Error()
				} else if errors.Is(err, ErrLimitUsageExceeded) {
					status = http.StatusTooManyRequests
					message = ErrLimitUsageExceeded.Error()
				}

				updateMetrics(apiKeyID, false)  // Log as invalid request
				logActivity(apiKeyID, r, false) // Log failed attempt
				cfg.ErrorHandler(w, message, status)
				return
			}

			// Check rate limit
			if keyDetails.RateLimit != nil {
				limiter := limiter.getLimiter(apiKeyID, *keyDetails.RateLimit)
				if !limiter.Allow() {
					// Add headers to inform about rate limiting
					w.Header().Set("X-RateLimit-Limit", strconv.Itoa(*keyDetails.RateLimit))
					w.Header().Set("X-RateLimit-Remaining", "0")
					w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))

					updateMetrics(apiKeyID, false)  // Log as invalid request
					logActivity(apiKeyID, r, false) // Log failed attempt
					cfg.ErrorHandler(w, ErrRateLimitExceeded.Error(), http.StatusTooManyRequests)
					return
				}
				// Add headers even for successful requests
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(*keyDetails.RateLimit))
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(int(limiter.Tokens())))
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
			}

			// Check IP restrictions
			clientIP := realip.FromRequest(r)
			if len(keyDetails.AllowedIPs) > 0 && !isIPAllowed(clientIP, keyDetails.AllowedIPs) {
				updateMetrics(apiKeyID, false)  // Log as invalid request
				logActivity(apiKeyID, r, false) // Log failed attempt
				cfg.ErrorHandler(w, ErrIPNotAllowed.Error(), http.StatusForbidden)
				return
			}

			// Check country restrictions (placeholder)
			if len(keyDetails.AllowedCountries) > 0 {
				fmt.Printf("country restriction check would happen here for countries: %v\n", keyDetails.AllowedCountries)
			}

			// Update metrics
			if err := updateMetrics(apiKeyID, true); err != nil {
				logActivity(apiKeyID, r, false) // Log failed attempt
				cfg.ErrorHandler(w, ErrInternalServerError.Error(), http.StatusInternalServerError)
				return
			}

			// Log successful activity
			if err := logActivity(apiKeyID, r, true); err != nil {
				// Just log the error, don't prevent the request from proceeding
				fmt.Printf("failed to log activity: %v\n", err)
			}

			// If everything is valid, call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

func IsRootKey(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle CORS preflight requests
			if r.Method == "OPTIONS" {
				handleCORS(w, r, nil, cfg)
				return
			}

			// Extract API key and ID
			apiKey, apiKeyID := extractAPIKey(r, cfg)
			if apiKey == "" || apiKeyID == "" {
				cfg.ErrorHandler(w, ErrMissingAPIKeyOrID.Error(), http.StatusUnauthorized)
				return
			}

			// Check if it's a valid root key
			isRoot, err := checkRootKey(apiKeyID, apiKey)
			if err != nil {
				updateMetrics(apiKeyID, false)  // Log as invalid request
				logActivity(apiKeyID, r, false) // Log failed attempt
				cfg.ErrorHandler(w, ErrFailedToVerifyRootKey.Error(), http.StatusInternalServerError)
				return
			}
			if !isRoot {
				updateMetrics(apiKeyID, false)  // Log as invalid request
				logActivity(apiKeyID, r, false) // Log failed attempt
				cfg.ErrorHandler(w, ErrInsufficientPrivileges.Error(), http.StatusUnauthorized)
				return
			}

			// If it's a valid root key, proceed with normal validation
			validateHandler := ValidateAPIKey(cfg)(next)
			validateHandler.ServeHTTP(w, r)
		})
	}
}

func isIPAllowed(clientIP string, allowedIPs []string) bool {
	for _, allowedIP := range allowedIPs {
		if strings.Contains(allowedIP, "/") {
			// It's a CIDR
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err == nil && ipNet.Contains(net.ParseIP(clientIP)) {
				return true
			}
		} else {
			// It's a single IP
			if clientIP == allowedIP {
				return true
			}
		}
	}
	return false
}

func logActivity(apiKeyID string, r *http.Request, success bool) error {
	cfg := getConfig()
	clientIP := realip.FromRequest(r)

	uuid, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	_, err = cfg.DB.Exec(`
		INSERT INTO _blackey_activity_logs (id, api_key_id, timestamp, user_agent, ip_address, region, success)
		VALUES ($1, (SELECT id FROM _blackey_api_keys WHERE id = $2), $3, $4, $5, $6, $7)
	`, uuid, apiKeyID, time.Now(), r.UserAgent(), clientIP, "Unknown", success)

	if err != nil {
		return fmt.Errorf("failed to log activity: %w", err)
	}

	return nil
}

func updateMetrics(apiKeyID string, isSuccess bool) error {
	cfg := getConfig()

	query := `
		UPDATE _blackey_metrics
		SET 
			total_access = total_access + 1,
			success_count = CASE WHEN $2 THEN success_count + 1 ELSE success_count END,
			invalid_count = CASE WHEN $2 THEN invalid_count ELSE invalid_count + 1 END,
			last_usage = $3
		WHERE api_key_id = $1
	`

	_, err := cfg.DB.Exec(query, apiKeyID, isSuccess, time.Now())

	if err != nil {
		return fmt.Errorf("failed to update metrics: %w", err)
	}

	return nil
}

// checkRootKey checks if the provided key is the root key
func checkRootKey(apiKeyID, apiKey string) (bool, error) {
	cfg := getConfig()

	var hashedKey string
	err := cfg.DB.QueryRow("SELECT key FROM _blackey_api_keys WHERE id = $1 AND is_root = true", apiKeyID).Scan(&hashedKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil // No root key found
		}
		return false, fmt.Errorf("failed to retrieve root key: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedKey), []byte(apiKey))
	return err == nil, nil
}

// validateKey checks if an API key is valid
func validateKey(id, key string) (*APIKey, error) {
	cfg := getConfig()

	var apiKey APIKey
	var expiresAt sql.NullTime
	var hashedKey string

	err := cfg.DB.QueryRow(`
		SELECT id, key, created_at, expires_at, is_active, 
			   allowed_ips, allowed_countries, cors_allowed_origins, 
			   rate_limit, limit_use
		FROM _blackey_api_keys
		WHERE id = $1 AND is_active = true
	`, id).Scan(
		&apiKey.ID, &hashedKey, &apiKey.CreatedAt, &expiresAt, &apiKey.IsActive,
		pq.Array(&apiKey.AllowedIPs), pq.Array(&apiKey.AllowedCountries), pq.Array(&apiKey.CORSAllowedOrigins),
		&apiKey.RateLimit, &apiKey.LimitUse,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("failed to query API key: %w", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedKey), []byte(key))
	if err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Check if the key has expired
	if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
		return nil, ErrExpiredAPIKey
	}

	// If expiresAt is valid, assign it to the APIKey struct
	if expiresAt.Valid {
		apiKey.ExpiresAt = &expiresAt.Time
	}

	// Check if the key has reached its usage limit
	if apiKey.LimitUse != nil {
		var usageCount int
		err := cfg.DB.QueryRow(`
        SELECT total_access
        FROM _blackey_metrics
        WHERE api_key_id = $1
    `, apiKey.ID).Scan(&usageCount)

		if err != nil {
			return nil, fmt.Errorf("failed to query API key usage: %w", err)
		}

		if usageCount >= *apiKey.LimitUse {
			return nil, ErrLimitUsageExceeded
		}
	}

	return &apiKey, nil
}

func handleCORS(w http.ResponseWriter, r *http.Request, keyDetails *APIKey, cfg MiddlewareConfig) {
	origin := r.Header.Get("Origin")

	apiKeyHeaderName := extractAPIKeyHeaderName(cfg)
	apiKeyIDHeaderName := extractAPIKeyIDHeaderName(cfg)

	// Set default CORS headers
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", fmt.Sprintf("Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, %v, %v", apiKeyHeaderName, apiKeyIDHeaderName))

	if keyDetails != nil && len(keyDetails.CORSAllowedOrigins) > 0 {
		// If we have specific allowed origins, check against them
		if isOriginAllowed(origin, keyDetails.CORSAllowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
	} else {
		// If no specific origins are set, allow all (you might want to change this default behavior)
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
	}
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" || allowedOrigin == origin {
			return true
		}
	}
	return false
}

// Helper function to extract API key header name from the request
func extractAPIKeyHeaderName(cfg MiddlewareConfig) string {
	apiKeyHeaderName := cfg.APIKeyHeaderName
	if apiKeyHeaderName == "" {
		apiKeyHeaderName = "Authorization"
	}
	return apiKeyHeaderName
}

// Helper function to extract API key ID header name from the request
func extractAPIKeyIDHeaderName(cfg MiddlewareConfig) string {
	apiKeyIDHeaderName := cfg.APIIDHeaderName
	if apiKeyIDHeaderName == "" {
		apiKeyIDHeaderName = "X-API-ID"
	}
	return apiKeyIDHeaderName
}

// Helper function to extract API key and ID from the request
func extractAPIKey(r *http.Request, cfg MiddlewareConfig) (string, string) {
	apiKeyHeaderName := extractAPIKeyHeaderName(cfg)
	apiKeyIDHeaderName := extractAPIKeyIDHeaderName(cfg)

	hearderPrefixName := cfg.HeaderPrefix
	if hearderPrefixName == "" {
		hearderPrefixName = "Bearer "
	}

	apiKeyHeader := r.Header.Get(apiKeyHeaderName)
	apiKey := strings.TrimPrefix(apiKeyHeader, hearderPrefixName)

	apiKeyID := r.Header.Get(apiKeyIDHeaderName)

	return apiKey, apiKeyID
}
