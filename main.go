package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ======================
// Enhanced Error Types
// ======================

type DatabaseError struct {
	Operation string
	Detail    string
	Err       error
	Target    string
	Code      string
	Advice    string
}

func (e *DatabaseError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n🚨 \033[1;31m%s FAILURE\033[0m\n", strings.ToUpper(e.Operation)))
	if e.Target != "" {
		sb.WriteString(fmt.Sprintf("├─ \033[1;36mTarget:\033[0m   %s\n", e.Target))
	}
	if e.Code != "" {
		sb.WriteString(fmt.Sprintf("├─ \033[1;36mCode:\033[0m     %s\n", e.Code))
	}
	sb.WriteString(fmt.Sprintf("├─ \033[1;36mReason:\033[0m   %s\n", e.Detail))
	if e.Advice != "" {
		sb.WriteString(fmt.Sprintf("╰─ \033[1;33m%s\033[0m\n", e.Advice))
	}
	if e.Err != nil {
		sb.WriteString(fmt.Sprintf("\n\033[2m🔧 Technical Details:\n%s\033[0m", e.Err))
	}
	return sb.String()
}

type ConfigError struct {
	Operation string
	Detail    string
	Variable  string
	Expected  string
	Err       error
}

func (e *ConfigError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n🔧 \033[1;33m%s CONFIGURATION ERROR\033[0m\n", strings.ToUpper(e.Operation)))
	if e.Variable != "" {
		sb.WriteString(fmt.Sprintf("├─ \033[1;36mVariable:\033[0m %s\n", e.Variable))
	}
	sb.WriteString(fmt.Sprintf("├─ \033[1;36mIssue:\033[0m    %s\n", e.Detail))
	sb.WriteString(fmt.Sprintf("╰─ \033[1;36mExpected:\033[0m %s\n", e.Expected))
	if e.Err != nil {
		sb.WriteString(fmt.Sprintf("\n\033[2m🔧 Technical Details:\n%s\033[0m", e.Err))
	}
	return sb.String()
}

// ======================
// Core Configuration
// ======================

type Config struct {
	Host        string
	Port        int
	SuperUser   string
	SuperPass   string
	User        string
	UserPass    string
	DBName      string
	UserFlags   string
	SSLMode     string
	SSLRootCert string
}

func (c Config) String() string {
	return fmt.Sprintf(
		"Config{Host:%q, Port:%d, SuperUser:%q, SuperPass:%s, User:%q, UserPass:%s, DBName:%q, UserFlags:%q, SSLMode:%q, SSLRootCert:%q}",
		c.Host,
		c.Port,
		c.SuperUser,
		redactString(c.SuperPass),
		c.User,
		redactString(c.UserPass),
		c.DBName,
		c.UserFlags,
		c.SSLMode,
		c.SSLRootCert,
	)
}

// ======================
// Helper Functions
// ======================

func highlight(s string) string {
	return fmt.Sprintf("\033[1;36m%s\033[0m", s)
}

func redactString(s string) string {
	if s == "" {
		return `""`
	}
	return `"[REDACTED]"`
}

func extractSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func isAuthError(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Severity == "FATAL" &&
			(pgErr.Code == "28P01" || // invalid_password
				pgErr.Code == "28000") // invalid_authorization
	}
	return false
}

func quoteLiteral(literal string) string {
	return "'" + strings.ReplaceAll(literal, "'", "''") + "'"
}

// ======================
// Configuration Loading
// ======================

func loadConfig() (Config, error) {
	var cfg Config
	var err error

	required := map[string]*string{
		"INIT_POSTGRES_SUPER_USER": &cfg.SuperUser,
		"INIT_POSTGRES_SUPER_PASS": &cfg.SuperPass,
		"INIT_POSTGRES_USER":       &cfg.User,
		"INIT_POSTGRES_PASS":       &cfg.UserPass,
		"INIT_POSTGRES_DBNAME":     &cfg.DBName,
		"INIT_POSTGRES_HOST":       &cfg.Host,
	}

	for key, ptr := range required {
		if *ptr, err = getRequiredEnv(key); err != nil {
			return Config{}, &ConfigError{
				Operation: "loading",
				Variable:  key,
				Detail:    "required environment variable not set",
				Expected:  "non-empty value",
			}
		}
	}

	if err := validatePassword(cfg.SuperPass); err != nil {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_SUPER_PASS",
			Detail:    "invalid superuser password",
			Expected:  err.Error(),
		}
	}

	if err := validatePassword(cfg.UserPass); err != nil {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_PASS",
			Detail:    "invalid application user password",
			Expected:  err.Error(),
		}
	}

	portStr := getEnvWithDefault("INIT_POSTGRES_PORT", "5432")
	cfg.Port, err = strconv.Atoi(portStr)
	if err != nil || cfg.Port < 1 || cfg.Port > 65535 {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_PORT",
			Detail:    "invalid port number",
			Expected:  "integer between 1-65535",
		}
	}

	cfg.UserFlags = os.Getenv("INIT_POSTGRES_USER_FLAGS")
	cfg.SSLMode = getEnvWithDefault("INIT_POSTGRES_SSLMODE", "disable")
	cfg.SSLRootCert = os.Getenv("INIT_POSTGRES_SSLROOTCERT")

	if err := validateSSLConfig(cfg.SSLMode, cfg.SSLRootCert); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validatePassword(pass string) error {
	if len(pass) < 12 {
		return fmt.Errorf("minimum 12 characters required")
	}
	return nil
}

func validateSSLConfig(sslMode, sslRootCert string) error {
	allowedModes := map[string]bool{
		"disable": true, "allow": true, "prefer": true,
		"require": true, "verify-ca": true, "verify-full": true,
	}

	if !allowedModes[sslMode] {
		return &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_SSLMODE",
			Detail:    "invalid SSL mode",
			Expected:  "one of: disable, allow, prefer, require, verify-ca, verify-full",
		}
	}

	if sslMode == "verify-ca" || sslMode == "verify-full" {
		if sslRootCert == "" {
			return &ConfigError{
				Operation: "validation",
				Variable:  "INIT_POSTGRES_SSLROOTCERT",
				Detail:    "SSL certificate required",
				Expected:  "path to SSL root certificate",
			}
		}
		if _, err := os.Stat(sslRootCert); err != nil {
			return &ConfigError{
				Operation: "validation",
				Variable:  "INIT_POSTGRES_SSLROOTCERT",
				Detail:    "SSL certificate file not found",
				Expected:  "valid path to CA certificate file",
				Err:       err,
			}
		}
	}

	return nil
}

func getRequiredEnv(key string) (string, error) {
	if value := os.Getenv(key); value != "" {
		return value, nil
	}
	return "", fmt.Errorf("not set")
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ======================
// Database Operations
// ======================

func connectPostgres(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	const maxAttempts = 30
	const baseDelay = 1 * time.Second

	escapedUser := url.QueryEscape(cfg.SuperUser)
	escapedPass := url.QueryEscape(cfg.SuperPass)
	escapedDB := url.QueryEscape(cfg.SuperUser)

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		escapedUser,
		escapedPass,
		cfg.Host,
		cfg.Port,
		escapedDB)

	parsedConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "configuration",
			Detail:    "invalid connection parameters",
			Target:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:    "Check special characters in credentials",
			Err:       err,
		}
	}

	tlsConfig, err := createTLSConfig(cfg.SSLMode, cfg.SSLRootCert, cfg.Host)
	if err != nil {
		return nil, err
	}
    
	parsedConfig.ConnConfig.TLSConfig = tlsConfig
	parsedConfig.MaxConns = 3
	parsedConfig.MinConns = 1
	parsedConfig.MaxConnLifetime = 5 * time.Minute
	parsedConfig.ConnConfig.ConnectTimeout = 10 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, parsedConfig)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "connection",
			Detail:    "failed to create connection pool",
			Target:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:    "Verify network connectivity and credentials",
			Err:       err,
		}
	}

	defer func() {
		if err != nil {
			pool.Close()
			log.Println("Closed connection pool due to initialization failure")
		}
	}()

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = pool.Ping(ctx)
		if err == nil {
			fmt.Printf("\033[32m✅ Successfully connected to %s:%d\033[0m\n", cfg.Host, cfg.Port)
			return pool, nil
		}

		if isAuthError(err) {
			return nil, &DatabaseError{
				Operation: "authentication",
				Detail:    "invalid credentials",
				Target:    fmt.Sprintf("%s@%s:%d", cfg.SuperUser, cfg.Host, cfg.Port),
				Code:      extractSQLState(err),
				Advice:    "Verify INIT_POSTGRES_SUPER_USER and INIT_POSTGRES_SUPER_PASS",
				Err:       err,
			}
		}

		if attempt < maxAttempts {
			fmt.Printf("\033[33m⏳ Connection validation attempt %d/%d failed: %v. Retrying...\033[0m\n",
				attempt, maxAttempts, err)
			select {
			case <-time.After(baseDelay * time.Duration(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, &DatabaseError{
		Operation: "connection",
		Detail:    fmt.Sprintf("failed after %d validation attempts", maxAttempts),
		Target:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Advice:    "Check database availability and network stability",
		Err:       err,
	}
}

func createTLSConfig(sslMode, sslRootCert, host string) (*tls.Config, error) {
    if sslMode == "disable" {
        return nil, nil
    }

    tlsConfig := &tls.Config{
        InsecureSkipVerify: sslMode == "require",
    }

    if sslMode == "verify-ca" || sslMode == "verify-full" {
        if sslRootCert != "" {
            certBytes, err := os.ReadFile(sslRootCert)
            if err != nil {
                return nil, &ConfigError{
                    Operation: "ssl-config",
                    Variable:  "INIT_POSTGRES_SSLROOTCERT",
                    Detail:    "failed to read SSL certificate",
                    Expected:  "valid certificate file",
                    Err:       err,
                }
            }

            tlsConfig.RootCAs = x509.NewCertPool()
            if !tlsConfig.RootCAs.AppendCertsFromPEM(certBytes) {
                return nil, &ConfigError{
                    Operation: "ssl-config",
                    Variable:  "INIT_POSTGRES_SSLROOTCERT",
                    Detail:    "failed to parse SSL certificate",
                    Expected:  "valid PEM-encoded certificate",
                }
            }
        }

        if sslMode == "verify-full" {
            tlsConfig.ServerName = host
        }
    }

    return tlsConfig, nil
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var exists bool
	err = tx.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)",
		cfg.User,
	).Scan(&exists)

	if err != nil {
		return &DatabaseError{
			Operation: "user check",
			Detail:    fmt.Sprintf("failed to verify user %q", cfg.User),
			Target:    cfg.User,
			Advice:    "Check database permissions and connection",
			Err:       err,
		}
	}

	flags, err := parseUserFlags(cfg.UserFlags)
	if err != nil {
		return &DatabaseError{
			Operation: "user-config",
			Detail:    fmt.Sprintf("invalid flags: %v", err),
			Target:    cfg.UserFlags,
			Advice:    "Use --createdb, --createrole, etc.",
			Err:       err,
		}
	}

	if !exists {
		fmt.Printf("\033[32m👤 Creating user %s...\033[0m\n", cfg.User)
		sql := fmt.Sprintf(
			`CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
			flags,
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user creation",
				Detail:    fmt.Sprintf("failed to create user %s", pgx.Identifier{cfg.User}.Sanitize()),
				Target:    cfg.User,
				Advice:    "Verify user creation privileges",
				Err:       err,
			}
		}
	} else {
		fmt.Printf("\033[32m👤 Updating role %s...\033[0m\n", cfg.User)
		sql := fmt.Sprintf(
			`ALTER ROLE %s WITH ENCRYPTED PASSWORD %s %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
			flags,
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user update",
				Detail:    fmt.Sprintf("failed to update role %s", pgx.Identifier{cfg.User}.Sanitize()),
				Target:    cfg.User,
				Advice:    "Check password requirements and user permissions",
				Err:       err,
			}
		}
	}

	return tx.Commit(ctx)
}

func parseUserFlags(flags string) (string, error) {
	var validFlags []string
	for _, flag := range strings.Fields(flags) {
		switch flag {
		case "--createdb", "--createrole", "--inherit", "--no-login",
			"--replication", "--superuser", "--no-superuser":
			validFlags = append(validFlags, strings.TrimPrefix(flag, "--"))
		default:
			return "", fmt.Errorf("unsupported user flag: %s", flag)
		}
	}
	return strings.Join(validFlags, " "), nil
}

func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var exists bool
	err = tx.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
		cfg.DBName,
	).Scan(&exists)

	if err != nil {
		return &DatabaseError{
			Operation: "database check",
			Detail:    fmt.Sprintf("failed to verify database %q", cfg.DBName),
			Target:    cfg.DBName,
			Advice:    "Check database connection and permissions",
			Err:       err,
		}
	}

	if !exists {
		fmt.Printf("\033[32m📦 Creating database %s...\033[0m\n", cfg.DBName)
		sql := fmt.Sprintf(
			`CREATE DATABASE %s OWNER %s`,
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize(),
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "database creation",
				Detail:    fmt.Sprintf("failed to create database %s", pgx.Identifier{cfg.DBName}.Sanitize()),
				Target:    cfg.DBName,
				Advice:    "Verify user has CREATEDB privilege",
				Err:       err,
			}
		}
	}

	fmt.Printf("\033[32m🔑 Granting privileges on %q to %q...\033[0m\n", cfg.DBName, cfg.User)
	sql := fmt.Sprintf(
		`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`,
		pgx.Identifier{cfg.DBName}.Sanitize(),
		pgx.Identifier{cfg.User}.Sanitize(),
	)

	if _, err = tx.Exec(ctx, sql); err != nil {
		return &DatabaseError{
			Operation: "privileges assignment",
			Detail:    fmt.Sprintf("failed to grant privileges on %s", pgx.Identifier{cfg.DBName}.Sanitize()),
			Target:    cfg.DBName,
			Advice:    "Check user permissions and database ownership",
			Err:       err,
		}
	}

	return tx.Commit(ctx)
}

// ======================
// Main Application
// ======================

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("\033[32m✅ Database initialization completed successfully\033[0m\n")
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	fmt.Printf("\033[34m📋 Loaded configuration:\n%s\033[0m\n", cfg.String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		pool.Close()
		fmt.Printf("Closed database connection pool")
	}()

	if err := createUser(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return err
	}

	return nil
}
