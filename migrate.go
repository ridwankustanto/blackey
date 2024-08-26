package blackey

import (
	"database/sql"
	"fmt"
)

// SetupTables creates necessary tables in the database
func SetupTables(db *sql.DB) error {
	// Create API Keys table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS _blackey_api_keys (
			id UUID PRIMARY KEY,
			key TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP WITH TIME ZONE,
			is_active BOOLEAN NOT NULL DEFAULT true,
			is_root BOOLEAN NOT NULL DEFAULT false,
			allowed_ips TEXT[],
			allowed_countries TEXT[],
			cors_allowed_origins TEXT[],
			rate_limit INTEGER,
			limit_use INTEGER
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create _blackey_api_keys table: %w", err)
	}

	// Create Activity Logs table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS _blackey_activity_logs (
			id UUID PRIMARY KEY,
			api_key_id UUID REFERENCES _blackey_api_keys(id),
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			user_agent TEXT,
			ip_address INET,
			region TEXT,
			success BOOLEAN NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create _blackey_activity_logs table: %w", err)
	}

	// Create Metrics table
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS _blackey_metrics (
			id UUID PRIMARY KEY,
			api_key_id UUID NOT NULL REFERENCES _blackey_api_keys(id),
			last_usage TIMESTAMP WITH TIME ZONE,
			success_count INTEGER NOT NULL DEFAULT 0,
			invalid_count INTEGER NOT NULL DEFAULT 0,
			total_access INTEGER NOT NULL DEFAULT 0,
			last_success_timestamp TIMESTAMP WITH TIME ZONE,
			last_invalid_timestamp TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE (api_key_id)
    	)
	`)
	if err != nil {
		return fmt.Errorf("failed to create _blackey_metrics table: %w", err)
	}

	// Create indexes for better query performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_key ON _blackey_api_keys(key)",
		"CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_is_active ON _blackey_api_keys(is_active)",
		"CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_is_root ON _blackey_api_keys(is_root)",
		"CREATE INDEX IF NOT EXISTS idx_blackey_activity_logs_api_key_id ON _blackey_activity_logs(api_key_id)",
		"CREATE INDEX IF NOT EXISTS idx_blackey_activity_logs_timestamp ON _blackey_activity_logs(timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_blackey_metrics_id ON _blackey_metrics(id)",
	}

	for _, idx := range indexes {
		_, err = db.Exec(idx)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}
