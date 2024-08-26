package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "github.com/lib/pq"
	"github.com/ridwankustanto/blackey"
)

func main() {
	// Connect to your database
	db, err := sql.Open("postgres", "your_connection_string")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Set up Blackey
	err = blackey.Initialize(db, "myapi_", 16)
	if err != nil {
		panic(err)
	}

	// Custom error handler example
	customErrorHandler := func(w http.ResponseWriter, message string, statusCode int) {
		response := map[string]interface{}{
			"error": message,
			"code":  statusCode,
			"data":  nil,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(response)
	}

	config := blackey.MiddlewareConfig{
		APIIDHeaderName:  "X-API-Key-ID",
		APIKeyHeaderName: "X-API-Key",
		HeaderPrefix:     "Bearer ",
		ErrorHandler:     customErrorHandler,
	}

	// Your API handler
	// Example implementation of middleware validation
	http.Handle("/api/", blackey.ValidateAPIKey(config)(logHelloMiddleware(http.HandlerFunc(yourAPIHandler))))
	http.Handle("/api/create-key", blackey.IsRootKey(config)(http.HandlerFunc(createAPIKeyHandler)))
	http.Handle("/api/revoke-key", blackey.IsRootKey(config)(http.HandlerFunc(revokeAPIKeyHandler)))
	http.Handle("/api/activate-key", blackey.IsRootKey(config)(http.HandlerFunc(activateAPIKeyHandler)))
	http.Handle("/api/update-key", blackey.IsRootKey(config)(http.HandlerFunc(updateRestrictionAPIKeyHandler)))
	http.ListenAndServe(":8080", nil)
}

func logHelloMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Hello, World!")
		next.ServeHTTP(w, r)
	})
}

func yourAPIHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hey, your API key works!")
}

func createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create new API key logic here
	rateLimit := 10
	limitUser := 5
	apiKey, err := blackey.CreateAPIKey(blackey.APIKey{
		AllowedIPs:         []string{"::1"},
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		AllowedCountries:   []string{"id"},
		RateLimit:          &rateLimit,
		LimitUse:           &limitUser,
	})
	if err != nil {
		http.Error(w, "Failed to create API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "New API key created successfully",
		"id":      apiKey.ID,
		"key":     apiKey.Key,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func revokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse Key ID from JSON param
	var payload map[string]any
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Failed to parse API key ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Revoke API key logic here
	err = blackey.RevokeAPIKey(payload["api_key_id"].(string))
	if err != nil {
		http.Error(w, "Failed to revoke API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "API key revoked successfully",
		"id":      payload["api_key_id"].(string),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func activateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse Key ID from JSON param
	var payload map[string]any
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Failed to parse API key ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Revoke API key logic here
	err = blackey.ActivateAPIKey(payload["api_key_id"].(string))
	if err != nil {
		http.Error(w, "Failed to revoke API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "API key activated successfully",
		"id":      payload["api_key_id"].(string),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func updateRestrictionAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse Key ID from JSON param
	var payload map[string]any
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Failed to parse API key ID: "+err.Error(), http.StatusBadRequest)
		return
	}

	keyID := payload["api_key_id"].(string)
	var expiresAt *time.Time
	expiresAtStr, ok := payload["expires_at"].(string)
	if !ok {
		expiresAt = nil
	} else {
		t, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			http.Error(w, "Invalid 'expires_at' format", http.StatusBadRequest)
			return
		}
		expiresAt = &t
	}

	allowedIPs, ok := payload["allowed_ips"].([]interface{})
	if !ok {
		allowedIPs = nil
	}
	allowedIPsStr := make([]string, len(allowedIPs))
	for i, v := range allowedIPs {
		allowedIPsStr[i] = v.(string)
	}
	if len(allowedIPsStr) == 0 {
		allowedIPsStr = nil
	}

	allowedCountries, ok := payload["allowed_countries"].([]interface{})
	if !ok {
		allowedCountries = nil
	}
	allowedCountriesStr := make([]string, len(allowedCountries))
	for i, v := range allowedCountries {
		allowedCountriesStr[i] = v.(string)
	}
	if len(allowedCountriesStr) == 0 {
		allowedCountriesStr = nil
	}

	rateLimitInt64 := payload["rate_limit"].(float64)
	rateLimit := int(rateLimitInt64)

	limitUsageInt64 := payload["limit_usage"].(float64)
	limitUsage := int(limitUsageInt64)

	corsAllowedOrigins, ok := payload["cors_allowed_origins"].([]interface{})
	if !ok {
		corsAllowedOrigins = nil
	}
	corsAllowedOriginsStr := make([]string, len(corsAllowedOrigins))
	for i, v := range corsAllowedOrigins {
		corsAllowedOriginsStr[i] = v.(string)
	}
	if len(corsAllowedOriginsStr) == 0 {
		corsAllowedOriginsStr = nil
	}

	// Revoke API key logic here
	err = blackey.UpdateAPIKeyRestrictions(keyID, blackey.APIKey{
		ExpiresAt:          expiresAt,
		AllowedIPs:         allowedIPsStr,
		AllowedCountries:   allowedCountriesStr,
		CORSAllowedOrigins: corsAllowedOriginsStr,
		RateLimit:          &rateLimit,
		LimitUse:           &limitUsage,
	})
	if err != nil {
		http.Error(w, "Failed to revoke API key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"message": "API key updated successfully",
		"id":      keyID,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
