package blackey

import (
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func TestSetupTables(t *testing.T) {
	// Create a mock database connection
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("An error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	// Set expectations
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS _blackey_api_keys").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS _blackey_activity_logs").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS _blackey_metrics").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_key").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_is_active").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_api_keys_is_root").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_activity_logs_api_key_id").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_activity_logs_timestamp").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE INDEX IF NOT EXISTS idx_blackey_metrics_id").WillReturnResult(sqlmock.NewResult(0, 0))

	// Call the function
	err = SetupTables(db)

	// Assert
	assert.NoError(t, err)

	// Ensure all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("There were unfulfilled expectations: %s", err)
	}
}

func TestSetupTablesError(t *testing.T) {
	// Create a mock database connection
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("An error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	// Set expectations for an error
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS _blackey_api_keys").WillReturnError(sql.ErrConnDone)

	// Call the function
	err = SetupTables(db)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create _blackey_api_keys table")

	// Ensure all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("There were unfulfilled expectations: %s", err)
	}
}
