package blackey

import (
	"database/sql"
	"errors"
	"fmt"
)

// GetMetrics retrieves usage metrics for an API key
func GetMetrics(apiKey string) (*Metrics, error) {
	cfg := getConfig()

	metrics := &Metrics{}

	err := cfg.DB.QueryRow(`
        SELECT 
            a.id,
            CASE WHEN a.limit_use IS NOT NULL THEN a.limit_use - m.total_access ELSE NULL END as remaining_uses,
            m.last_usage,
            m.success_count,
            m.invalid_count,
            m.total_access
        FROM 
            _blackey_api_keys a
        JOIN 
            _blackey_metrics m ON a.id = m.api_key_id
        WHERE 
            a.key = $1 AND a.is_active = true
    `, apiKey).Scan(
		&metrics.APIKeyID,
		&metrics.RemainingUses,
		&metrics.LastUsage,
		&metrics.SuccessCount,
		&metrics.InvalidCount,
		&metrics.TotalAccess,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("failed to get metrics: %w", err)
	}

	return metrics, nil
}
