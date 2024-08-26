package blackey

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestGetMetrics(t *testing.T) {
	// Create a mock database connection
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("An error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	// Set up the config
	config = &Config{
		DB: db,
	}

	// Test case 1: Successful metrics retrieval
	t.Run("Successful Metrics Retrieval", func(t *testing.T) {
		apiKey := "test_key_123"
		apiKeyID := "abc123"
		lastUsage := time.Now().Add(-1 * time.Hour)
		remainingUses := 500
		successCount := 1500
		invalidCount := 50
		totalAccess := 1550

		rows := sqlmock.NewRows([]string{"id", "remaining_uses", "last_usage", "success_count", "invalid_count", "total_access"}).
			AddRow(apiKeyID, remainingUses, lastUsage, successCount, invalidCount, totalAccess)

		mock.ExpectQuery("SELECT (.+) FROM _blackey_api_keys a JOIN _blackey_metrics m ON").
			WithArgs(apiKey).
			WillReturnRows(rows)

		metrics, err := GetMetrics(apiKey)

		assert.NoError(t, err)
		assert.NotNil(t, metrics)
		assert.Equal(t, apiKeyID, metrics.APIKeyID)
		assert.Equal(t, &remainingUses, metrics.RemainingUses)
		assert.Equal(t, lastUsage.UTC(), metrics.LastUsage.UTC())
		assert.Equal(t, successCount, metrics.SuccessCount)
		assert.Equal(t, invalidCount, metrics.InvalidCount)
		assert.Equal(t, totalAccess, metrics.TotalAccess)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 2: API key not found
	t.Run("API Key Not Found", func(t *testing.T) {
		apiKey := "nonexistent_key"

		mock.ExpectQuery("SELECT (.+) FROM _blackey_api_keys a JOIN _blackey_metrics m ON").
			WithArgs(apiKey).
			WillReturnError(sql.ErrNoRows)

		metrics, err := GetMetrics(apiKey)

		assert.Error(t, err)
		assert.Nil(t, metrics)
		assert.Equal(t, ErrAPIKeyNotFound, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	// Test case 3: Database error
	t.Run("Database Error", func(t *testing.T) {
		apiKey := "test_key_456"

		mock.ExpectQuery("SELECT (.+) FROM _blackey_api_keys a JOIN _blackey_metrics m ON").
			WithArgs(apiKey).
			WillReturnError(sql.ErrConnDone)

		metrics, err := GetMetrics(apiKey)

		assert.Error(t, err)
		assert.Nil(t, metrics)
		assert.Contains(t, err.Error(), "failed to get metrics")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}
