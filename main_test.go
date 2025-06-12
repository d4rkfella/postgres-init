package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRedactString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Short string",
			input:    "abc",
			expected: "a**",
		},
		{
			name:     "Longer string",
			input:    "password123",
			expected: "p**********",
		},
		{
			name:     "Single character string",
			input:    "a",
			expected: "*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactString(tc.input); got != tc.expected {
				t.Errorf("redactString(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestQuoteLiteral(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "Simple string",
			input:    "test",
			expected: "'test'",
		},
		{
			name:     "String with single quote",
			input:    "test's",
			expected: "'test''s'",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quoteLiteral(tc.input); got != tc.expected {
				t.Errorf("quoteLiteral(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestTlsVersionToString(t *testing.T) {
	testCases := []struct {
		name     string
		input    uint16
		expected string
	}{
		{
			name:     "TLS 1.0",
			input:    0x0301,
			expected: "TLS 1.0",
		},
		{
			name:     "TLS 1.1",
			input:    0x0302,
			expected: "TLS 1.1",
		},
		{
			name:     "TLS 1.2",
			input:    0x0303,
			expected: "TLS 1.2",
		},
		{
			name:     "TLS 1.3",
			input:    0x0304,
			expected: "TLS 1.3",
		},
		{
			name:     "Unknown",
			input:    0x0000,
			expected: "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tlsVersionToString(tc.input); got != tc.expected {
				t.Errorf("tlsVersionToString(%d) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestVersionSecurityStatus(t *testing.T) {
	testCases := []struct {
		name     string
		input    uint16
		expected string
	}{
		{
			name:     "TLS 1.0",
			input:    0x0301,
			expected: "(\033[31mINSECURE\033[0m)",
		},
		{
			name:     "TLS 1.1",
			input:    0x0302,
			expected: "(\033[31mINSECURE\033[0m)",
		},
		{
			name:     "TLS 1.2",
			input:    0x0303,
			expected: "(\033[33mOK\033[0m)",
		},
		{
			name:     "TLS 1.3",
			input:    0x0304,
			expected: "(\033[32mSECURE\033[0m)",
		},
		{
			name:     "Unknown",
			input:    0x0000,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionSecurityStatus(tc.input); got != tc.expected {
				t.Errorf("versionSecurityStatus(%d) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestParseUserFlags(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expected      string
		expectedError bool
	}{
		{
			name:          "Empty string",
			input:         "",
			expected:      "",
			expectedError: false,
		},
		{
			name:          "Single flag",
			input:         "CREATEDB",
			expected:      "CREATEDB",
			expectedError: false,
		},
		{
			name:          "Multiple flags",
			input:         "CREATEDB,CREATEROLE,LOGIN",
			expected:      "CREATEDB CREATEROLE LOGIN",
			expectedError: false,
		},
		{
			name:          "Flags with spaces",
			input:         " CREATEDB ,  CREATEROLE ",
			expected:      "CREATEDB CREATEROLE",
			expectedError: false,
		},
		{
			name:          "Invalid flag",
			input:         "DROPDB",
			expected:      "",
			expectedError: true,
		},
		{
			name:          "Mixed valid and invalid flags",
			input:         "CREATEDB,DROPDB",
			expected:      "",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUserFlags(tc.input)
			if (err != nil) != tc.expectedError {
				t.Errorf("parseUserFlags(%q) error = %v; expectedError %v", tc.input, err, tc.expectedError)
			}
			if got != tc.expected {
				t.Errorf("parseUserFlags(%q) = %q; want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			parts := strings.SplitN(env, "=", 2)
			if err := os.Setenv(parts[0], parts[1]); err != nil {
				t.Fatalf("Failed to set environment variable: %v", err)
			}
		}
	}()

	testCases := []struct {
		name          string
		env           map[string]string
		expectedError bool
		expected      Config
	}{
		{
			name: "Valid config",
			env: map[string]string{
				"POSTGRES_HOST":              "localhost",
				"POSTGRES_PORT":              "5432",
				"POSTGRES_SUPER_USER":        "postgres",
				"POSTGRES_SUPER_PASS":        "SuperSecure1!",
				"POSTGRES_USER":              "user",
				"POSTGRES_PASS":              "UserPassw0rd$",
				"POSTGRES_DBNAME":            "testdb",
				"POSTGRES_USER_FLAGS":        "CREATEDB",
				"POSTGRES_SSLMODE":           "disable",
				"POSTGRES_SSL_ROOTCERT_PATH": "/path/to/cert",
			},
			expectedError: false,
			expected: Config{
				Host:        "localhost",
				Port:        "5432",
				SuperUser:   "postgres",
				SuperPass:   "SuperSecure1!",
				User:        "user",
				UserPass:    "UserPassw0rd$",
				DBName:      "testdb",
				UserFlags:   "CREATEDB",
				SSLMode:     "disable",
				SSLRootCert: "/path/to/cert",
			},
		},
		{
			name: "Missing required env var",
			env: map[string]string{
				"POSTGRES_HOST": "localhost",
			},
			expectedError: true,
		},
		{
			name: "Invalid password",
			env: map[string]string{
				"POSTGRES_HOST":          "localhost",
				"POSTGRES_PORT":          "5432",
				"POSTGRES_SUPER_USER":    "postgres",
				"POSTGRES_SUPER_PASS":    "pass",
				"POSTGRES_USER":          "user",
				"POSTGRES_PASS":          "password",
				"POSTGRES_DBNAME":        "testdb",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Clearenv()
			for k, v := range tc.env {
				if err := os.Setenv(k, v); err != nil {
					t.Fatalf("Failed to set environment variable: %v", err)
				}
			}

			cfg, err := loadConfig()
			if (err != nil) != tc.expectedError {
				t.Errorf("loadConfig() error = %v; expectedError %v", err, tc.expectedError)
			}
			if !tc.expectedError {
				// We need to parse flags for comparison
				expectedFlags, _ := parseUserFlags(tc.expected.UserFlags)
				cfg.UserFlags = expectedFlags
				tc.expected.UserFlags = expectedFlags
				if fmt.Sprintf("%v", cfg) != fmt.Sprintf("%v", tc.expected) {
					t.Errorf("loadConfig() = %+v; want %+v", cfg, tc.expected)
				}
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	testCases := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "Valid password",
			password:    "Test123!@#$%^",
			expectError: false,
		},
		{
			name:        "Too short",
			password:    "Test1!",
			expectError: true,
		},
		{
			name:        "No uppercase",
			password:    "test123!@#$%^",
			expectError: true,
		},
		{
			name:        "No lowercase",
			password:    "TEST123!@#$%^",
			expectError: true,
		},
		{
			name:        "No numbers",
			password:    "Test!@#$%^",
			expectError: true,
		},
		{
			name:        "No special characters",
			password:    "Test123456",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassword(tc.password)
			if (err != nil) != tc.expectError {
				t.Errorf("validatePassword(%q) error = %v, expectError = %v", tc.password, err, tc.expectError)
			}
		})
	}
}

func TestClassifyPostgresError(t *testing.T) {
	cfg := Config{
		Host:      "testhost",
		SuperUser: "testsuper",
		User:      "testuser",
		DBName:    "testdb",
	}

	testCases := []struct {
		name          string
		err           error
		operation     string
		expectedCode  string
		expectedDetail string
	}{
		{
			name:      "Connection Authentication Error",
			err:       &pgconn.PgError{
				Severity:         "ERROR",
				Code:            "28P01",
				Message:         "password authentication failed",
				Position:        0,
				InternalQuery:   "",
				InternalPosition: 0,
				Where:           "",
				SchemaName:      "",
				TableName:       "",
				ColumnName:      "",
				DataTypeName:    "",
				ConstraintName:  "",
				File:           "",
				Line:           0,
				Routine:        "",
			},
			operation:     "connection",
			expectedCode:  "28P01",
			expectedDetail: "invalid password (SQLSTATE 28P01)",
		},
		{
			name:      "SSL Required Error",
			err:       &pgconn.PgError{
				Severity:         "ERROR",
				Code:            "28000",
				Message:         "SSL off",
				Position:        0,
				InternalQuery:   "",
				InternalPosition: 0,
				Where:           "",
				SchemaName:      "",
				TableName:       "",
				ColumnName:      "",
				DataTypeName:    "",
				ConstraintName:  "",
				File:           "",
				Line:           0,
				Routine:        "",
			},
			operation:     "connection",
			expectedCode:  "28000",
			expectedDetail: "server requires SSL connection (SQLSTATE 28000)",
		},
		{
			name:      "Database Already Exists",
			err:       &pgconn.PgError{
				Severity:         "ERROR",
				Code:            "42P04",
				Message:         "database already exists",
				Position:        0,
				InternalQuery:   "",
				InternalPosition: 0,
				Where:           "",
				SchemaName:      "",
				TableName:       "",
				ColumnName:      "",
				DataTypeName:    "",
				ConstraintName:  "",
				File:           "",
				Line:           0,
				Routine:        "",
			},
			operation:     "database_creation",
			expectedCode:  "42P04",
			expectedDetail: "database already exists (SQLSTATE 42P04)",
		},
		{
			name:      "Insufficient Privileges",
			err:       &pgconn.PgError{
				Severity:         "ERROR",
				Code:            "42501",
				Message:         "permission denied to create database",
				Position:        0,
				InternalQuery:   "",
				InternalPosition: 0,
				Where:           "",
				SchemaName:      "",
				TableName:       "",
				ColumnName:      "",
				DataTypeName:    "",
				ConstraintName:  "",
				File:           "",
				Line:           0,
				Routine:        "",
			},
			operation:     "database_creation",
			expectedCode:  "42501",
			expectedDetail: "insufficient privileges to create database (SQLSTATE 42501)",
		},
		{
			name:      "Unhandled Error",
			err:       &pgconn.PgError{
				Severity:         "ERROR",
				Code:            "08000",
				Message:         "connection exception",
				Position:        0,
				InternalQuery:   "",
				InternalPosition: 0,
				Where:           "",
				SchemaName:      "",
				TableName:       "",
				ColumnName:      "",
				DataTypeName:    "",
				ConstraintName:  "",
				File:           "",
				Line:           0,
				Routine:        "",
			},
			operation:     "connection",
			expectedCode:  "08000",
			expectedDetail: "connection failed (SQLSTATE 08000)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dbErr := classifyPostgresError(tc.err, cfg, tc.operation)
			if dbErr.Code != tc.expectedCode {
				t.Errorf("expected error code %s but got %s", tc.expectedCode, dbErr.Code)
			}
			if dbErr.Detail != tc.expectedDetail {
				t.Errorf("expected error detail %q but got %q", tc.expectedDetail, dbErr.Detail)
			}
		})
	}
}

func TestClassifyPostgresError_Comprehensive(t *testing.T) {
	cfg := Config{
		Host:      "localhost",
		SuperUser: "admin",
		User:      "testuser",
		DBName:    "testdb",
	}

	t.Run("Non-PostgreSQL error", func(t *testing.T) {
		err := errors.New("some network error")
		derr := classifyPostgresError(err, cfg, "connection")
		if derr.Code != "UNKNOWN" || !strings.Contains(derr.Detail, "non-PostgreSQL error") {
			t.Errorf("Expected UNKNOWN code for non-PostgreSQL error, got %v", derr)
		}
	})

	pgErr := func(code, msg string) error {
		return &pgconn.PgError{Code: code, Message: msg}
	}

	t.Run("Connection: invalid password", func(t *testing.T) {
		err := classifyPostgresError(pgErr("28P01", "bad password"), cfg, "connection")
		if !strings.Contains(err.Detail, "invalid password") || err.Code != "28P01" {
			t.Errorf("Expected invalid password, got %v", err)
		}
	})

	t.Run("Connection: SSL required", func(t *testing.T) {
		err := classifyPostgresError(pgErr("28000", "SSL off"), cfg, "connection")
		if !strings.Contains(err.Detail, "server requires SSL connection") || err.Code != "28000" {
			t.Errorf("Expected server requires SSL connection, got %v", err)
		}
	})

	t.Run("Connection: pg_hba.conf", func(t *testing.T) {
		err := classifyPostgresError(pgErr("28000", "not SSL off"), cfg, "connection")
		if !strings.Contains(err.Detail, "pg_hba.conf") || err.Code != "28000" {
			t.Errorf("Expected pg_hba.conf, got %v", err)
		}
	})

	t.Run("Connection: default", func(t *testing.T) {
		err := classifyPostgresError(pgErr("99999", "other"), cfg, "connection")
		if !strings.Contains(err.Detail, "connection failed") || err.Code != "99999" {
			t.Errorf("Expected connection failed, got %v", err)
		}
	})

	t.Run("User management: role exists", func(t *testing.T) {
		err := classifyPostgresError(pgErr("42710", "role exists"), cfg, "user_management")
		if !strings.Contains(err.Detail, "role already exists") || err.Code != "42710" {
			t.Errorf("Expected role already exists, got %v", err)
		}
	})

	t.Run("User management: insufficient privileges", func(t *testing.T) {
		err := classifyPostgresError(pgErr("42501", "no privs"), cfg, "user_management")
		if !strings.Contains(err.Detail, "insufficient privileges") || err.Code != "42501" {
			t.Errorf("Expected insufficient privileges, got %v", err)
		}
	})

	t.Run("User management: default", func(t *testing.T) {
		err := classifyPostgresError(pgErr("99999", "other"), cfg, "user_management")
		if !strings.Contains(err.Detail, "user management operation failed") || err.Code != "99999" {
			t.Errorf("Expected user management operation failed, got %v", err)
		}
	})

	for _, op := range []string{"database_management", "database_creation", "privileges_assignment"} {
		t.Run(op+": db exists", func(t *testing.T) {
			err := classifyPostgresError(pgErr("42P04", "db exists"), cfg, op)
			if !strings.Contains(err.Detail, "database already exists") || err.Code != "42P04" {
				t.Errorf("Expected database already exists, got %v", err)
			}
		})
		t.Run(op+": insufficient privs", func(t *testing.T) {
			err := classifyPostgresError(pgErr("42501", "no privs"), cfg, op)
			if !strings.Contains(err.Detail, "insufficient privileges") || err.Code != "42501" {
				t.Errorf("Expected insufficient privileges, got %v", err)
			}
		})
		t.Run(op+": db does not exist", func(t *testing.T) {
			err := classifyPostgresError(pgErr("3D000", "no db"), cfg, op)
			if !strings.Contains(err.Detail, "does not exist") || err.Code != "3D000" {
				t.Errorf("Expected database does not exist, got %v", err)
			}
		})
		t.Run(op+": default", func(t *testing.T) {
			err := classifyPostgresError(pgErr("99999", "other"), cfg, op)
			if !strings.Contains(err.Detail, "database management operation failed") || err.Code != "99999" {
				t.Errorf("Expected database management operation failed, got %v", err)
			}
		})
	}

	t.Run("Unknown operation", func(t *testing.T) {
		err := classifyPostgresError(pgErr("99999", "other"), cfg, "unknown_op")
		if !strings.Contains(err.Detail, "unhandled operation type") || err.Code != "99999" {
			t.Errorf("Expected unhandled operation type, got %v", err)
		}
	})
}

func TestConnectPostgres(t *testing.T) {
	originalEnv := os.Environ()
	defer func() {
		os.Clearenv()
		for _, env := range originalEnv {
			parts := strings.SplitN(env, "=", 2)
			if err := os.Setenv(parts[0], parts[1]); err != nil {
				t.Fatalf("Failed to set environment variable: %v", err)
			}
		}
	}()

	testCases := []struct {
		name          string
		config        Config
		expectedError bool
		errorCode     string
	}{
		{
			name: "Valid configuration",
			config: Config{
				Host:      "localhost",
				Port:      "5432",
				SuperUser: "postgres",
				SuperPass: "postgres", // Match the password we set in the Docker container
				SSLMode:   "disable",
			},
			expectedError: false,
		},
		{
			name: "Invalid password",
			config: Config{
				Host:      "localhost",
				Port:      "5432",
				SuperUser: "postgres",
				SuperPass: "wrongpassword",
				SSLMode:   "disable",
			},
			expectedError: true,
			errorCode:     "28P01",
		},
		{
			name: "Invalid host",
			config: Config{
				Host:      "nonexistent",
				Port:      "5432",
				SuperUser: "postgres",
				SuperPass: "postgres",
				SSLMode:   "disable",
			},
			expectedError: true,
			errorCode:     "UNKNOWN", // Connection errors are non-PostgreSQL errors
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db, err := connectPostgres(ctx, tc.config)

			if tc.expectedError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}

				var dbErr *DatabaseError
				if !errors.As(err, &dbErr) {
					t.Errorf("expected DatabaseError but got %T", err)
					return
				}

				if tc.errorCode != "" && dbErr.Code != tc.errorCode {
					t.Errorf("expected error code %s but got %s", tc.errorCode, dbErr.Code)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if db == nil {
					t.Error("expected non-nil database connection")
					return
				}
				db.Close()
			}
		})
	}
}

func TestPrintSSLInfo(t *testing.T) {
	state := tls.ConnectionState{
		Version: tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		VerifiedChains: [][]*x509.Certificate{},
	}
	cfg := Config{
		Host:    "localhost",
		SSLMode: "require",
	}
	output := captureOutput(func() {
		printSSLInfo(state, cfg)
	})
	if !strings.Contains(output, "SSL Connection State") {
		t.Errorf("Expected output to contain 'SSL Connection State', got %q", output)
	}
	if !strings.Contains(output, "ENCRYPTED") {
		t.Errorf("Expected output to contain 'ENCRYPTED', got %q", output)
	}
	if !strings.Contains(output, "TLS 1.2") {
		t.Errorf("Expected output to contain 'TLS 1.2', got %q", output)
	}
}

func TestHandleSuccessfulConnection_Unencrypted(t *testing.T) {
	cfg := Config{
		Host:    "localhost",
		Port:    "5432",
		SSLMode: "disable",
	}
	output := captureOutput(func() {
		// nil pool is fine since SSLMode is disable and code path doesn't use it
		pool, err := handleSuccessfulConnection(nil, cfg)
		if err != nil {
			t.Fatalf("handleSuccessfulConnection failed: %v", err)
		}
		if pool != nil {
			t.Fatal("expected nil pool")
		}
	})
	if !strings.Contains(output, "UNENCRYPTED") {
		t.Errorf("Expected output to contain 'UNENCRYPTED', got %q", output)
	}
}

// Helper function to capture stdout output
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	if err := w.Close(); err != nil {
		panic(fmt.Sprintf("Failed to close writer: %v", err))
	}

	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic(fmt.Sprintf("Failed to copy data: %v", err))
	}
	return buf.String()
}

func TestIsFatalError(t *testing.T) {
	testCases := []struct {
		name      string
		operation string
		expected  bool
	}{
		{
			name:      "Authentication operation",
			operation: "authentication",
			expected:  true,
		},
		{
			name:      "SSL configuration operation",
			operation: "ssl_configuration",
			expected:  true,
		},
		{
			name:      "Non-fatal operation",
			operation: "database_creation",
			expected:  false,
		},
		{
			name:      "Empty operation",
			operation: "",
			expected:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFatalError(tc.operation); got != tc.expected {
				t.Errorf("isFatalError(%q) = %v; want %v", tc.operation, got, tc.expected)
			}
		})
	}
}

func TestExtractSQLState(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "PostgreSQL error",
			err: &pgconn.PgError{
				Code: "42P01",
				Message: "relation does not exist",
			},
			expected: "42P01",
		},
		{
			name:     "Non-PostgreSQL error",
			err:      fmt.Errorf("some error"),
			expected: "",
		},
		{
			name:     "Nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractSQLState(tc.err); got != tc.expected {
				t.Errorf("extractSQLState(%v) = %q; want %q", tc.err, got, tc.expected)
			}
		})
	}
}

func TestDatabaseError_Error(t *testing.T) {
	testCases := []struct {
		name     string
		err      *DatabaseError
		expected string
	}{
		{
			name: "Full error details",
			err: &DatabaseError{
				Operation: "connection",
				Detail:    "connection failed",
				Target:    "localhost",
				Code:      "08000",
				Advice:    "Check network connectivity",
				Err:       fmt.Errorf("underlying error"),
			},
			expected: "\n🚨 \033[1;31mCONNECTION FAILURE\033[0m\n" +
				"├─ \033[1;36mTarget:\033[0m   localhost\n" +
				"├─ \033[1;36mCode:\033[0m     08000\n" +
				"├─ \033[1;36mReason:\033[0m   connection failed\n" +
				"╰─ \033[1;33mCheck network connectivity\033[0m\n\n" +
				"\033[2m🔧 Technical Details:\nunderlying error\033[0m",
		},
		{
			name: "Minimal error details",
			err: &DatabaseError{
				Operation: "test",
				Detail:    "test error",
			},
			expected: "\n🚨 \033[1;31mTEST FAILURE\033[0m\n" +
				"├─ \033[1;36mReason:\033[0m   test error\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.expected {
				t.Errorf("Error() = %q; want %q", got, tc.expected)
			}
		})
	}
}

func TestConfigError_Error(t *testing.T) {
	testCases := []struct {
		name     string
		err      *ConfigError
		expected string
	}{
		{
			name: "Full error details",
			err: &ConfigError{
				Operation: "loading",
				Detail:    "invalid value",
				Variable:  "POSTGRES_HOST",
				Expected:  "non-empty string",
				Err:       fmt.Errorf("underlying error"),
			},
			expected: "\n🔧 \033[1;33mLOADING CONFIGURATION ERROR\033[0m\n" +
				"├─ \033[1;36mVariable:\033[0m POSTGRES_HOST\n" +
				"├─ \033[1;36mIssue:\033[0m    invalid value\n" +
				"╰─ \033[1;36mExpected:\033[0m non-empty string\n\n" +
				"\033[2m🔧 Technical Details:\nunderlying error\033[0m",
		},
		{
			name: "Minimal error details",
			err: &ConfigError{
				Operation: "test",
				Detail:    "test error",
				Expected:  "test expected",
			},
			expected: "\n🔧 \033[1;33mTEST CONFIGURATION ERROR\033[0m\n" +
				"├─ \033[1;36mIssue:\033[0m    test error\n" +
				"╰─ \033[1;36mExpected:\033[0m test expected\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.expected {
				t.Errorf("Error() = %q; want %q", got, tc.expected)
			}
		})
	}
}

func TestClassifyPostgresError_AdditionalCases(t *testing.T) {
	cfg := Config{
		Host:      "testhost",
		SuperUser: "testsuper",
		User:      "testuser",
		DBName:    "testdb",
	}

	testCases := []struct {
		name           string
		err            error
		operation      string
		expectedCode   string
		expectedDetail string
		expectedAdvice string
	}{
		{
			name: "Database does not exist",
			err: &pgconn.PgError{
				Code:    "3D000",
				Message: "database does not exist",
			},
			operation:      "database_management",
			expectedCode:   "3D000",
			expectedDetail: "database does not exist (SQLSTATE 3D000)",
			expectedAdvice: "Verify database name or create it first",
		},
		{
			name: "Unknown operation type",
			err: &pgconn.PgError{
				Code:    "99999",
				Message: "unknown error",
			},
			operation:      "unknown_operation",
			expectedCode:   "99999",
			expectedDetail: "unhandled operation type: unknown_operation (SQLSTATE 99999)",
			expectedAdvice: "Contact system administrator",
		},
		{
			name: "Non-PostgreSQL error",
			err:  fmt.Errorf("network error"),
			operation:      "connection",
			expectedCode:   "UNKNOWN",
			expectedDetail: "non-PostgreSQL error: network error",
			expectedAdvice: "Check the error details and system logs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyPostgresError(tc.err, cfg, tc.operation)
			if err.Code != tc.expectedCode {
				t.Errorf("expected code %s, got %s", tc.expectedCode, err.Code)
			}
			if err.Detail != tc.expectedDetail {
				t.Errorf("expected detail %s, got %s", tc.expectedDetail, err.Detail)
			}
			if err.Advice != tc.expectedAdvice {
				t.Errorf("expected advice %s, got %s", tc.expectedAdvice, err.Advice)
			}
		})
	}
}

func TestValidateSSLConfig(t *testing.T) {
	// Create a temporary directory for SSL certificate tests
	tempDir, err := os.MkdirTemp("", "ssl-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temp directory: %v", err)
		}
	}()

	// Create a dummy certificate file
	certPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(certPath, []byte("dummy cert"), 0644); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "Valid disable mode",
			config: Config{
				SSLMode: "disable",
			},
			expectError: false,
		},
		{
			name: "Valid require mode with cert",
			config: Config{
				SSLMode:     "require",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Valid verify-ca mode with cert",
			config: Config{
				SSLMode:     "verify-ca",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Valid verify-full mode with cert",
			config: Config{
				SSLMode:     "verify-full",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Missing cert for require mode",
			config: Config{
				SSLMode:     "require",
				SSLRootCert: "",
			},
			expectError: false,
		},
		{
			name: "Invalid SSL mode",
			config: Config{
				SSLMode: "invalid",
			},
			expectError: true,
		},
		{
			name: "Non-existent cert file",
			config: Config{
				SSLMode:     "require",
				SSLRootCert: "/nonexistent/cert.crt",
			},
			expectError: false,
		},
		{
			name: "Valid require mode with cert",
			config: Config{
				SSLMode:     "require",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Valid verify-ca mode with cert",
			config: Config{
				SSLMode:     "verify-ca",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Valid verify-full mode with cert",
			config: Config{
				SSLMode:     "verify-full",
				SSLRootCert: certPath,
			},
			expectError: false,
		},
		{
			name: "Missing cert for verify-ca mode",
			config: Config{
				SSLMode:     "verify-ca",
				SSLRootCert: "",
			},
			expectError: true,
		},
		{
			name: "Missing cert for verify-full mode",
			config: Config{
				SSLMode:     "verify-full",
				SSLRootCert: "",
			},
			expectError: true,
		},
		{
			name: "Invalid SSL mode",
			config: Config{
				SSLMode:     "invalid-mode",
				SSLRootCert: certPath,
			},
			expectError: true,
		},
		{
			name: "Non-existent cert file for verify-ca mode",
			config: Config{
				SSLMode:     "verify-ca",
				SSLRootCert: "/nonexistent/cert.crt",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSSLConfig(tc.config)
			if (err != nil) != tc.expectError {
				t.Errorf("validateSSLConfig() error = %v, expectError = %v", err, tc.expectError)
			}
		})
	}
}