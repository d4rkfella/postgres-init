package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"strconv"
	"time"
	"log"

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
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf(`
🔧 \033[1;33mCONFIG ERROR\033[0m
├─ \033[1;36mVariable:\033[0m %s
├─ \033[1;36mIssue:\033[0m    %s
╰─ \033[1;36mExpected:\033[0m %s`,
		highlight(e.Variable),
		e.Detail,
		e.Expected)
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
	return fmt.Sprintf("\033[1;35m%s\033[0m", s)
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
			 pgErr.Code == "28000")   // invalid_authorization
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

	if (sslMode == "verify-ca" || sslMode == "verify-full") && sslRootCert == "" {
		return &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_SSLROOTCERT",
			Detail:    "SSL certificate required",
			Expected:  "path to SSL root certificate",
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

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.SuperUser,
		cfg.SuperPass,
		cfg.Host,
		cfg.Port,
		cfg.SuperUser,
		cfg.SSLMode)

	if cfg.SSLRootCert != "" {
		connStr += fmt.Sprintf("&sslrootcert=%s", cfg.SSLRootCert)
	}

	parsedConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "configuration",
			Detail:   "invalid connection parameters",
			Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:   "Check host, port, and SSL configuration",
			Err:      err,
		}
	}

	parsedConfig.MaxConns = 3
	parsedConfig.MinConns = 1
	parsedConfig.MaxConnLifetime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, parsedConfig)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "connection",
			Detail:   "failed to create connection pool",
			Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:   "Verify network connectivity and database availability",
			Err:      err,
		}
	}

	defer func() {
		if err != nil {
			pool.Close()
		}
	}()

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = pool.Ping(ctx)
		if err == nil {
			colorPrint(fmt.Sprintf("✅ Successfully connected to %s:%d", cfg.Host, cfg.Port), "green")
			return pool, nil
		}

		if isAuthError(err) {
			return nil, &DatabaseError{
				Operation: "authentication",
				Detail:   "invalid credentials",
				Target:   fmt.Sprintf("%s@%s:%d", cfg.SuperUser, cfg.Host, cfg.Port),
				Code:     extractSQLState(err),
				Advice:   "Verify INIT_POSTGRES_SUPER_USER and INIT_POSTGRES_SUPER_PASS",
				Err:      err,
			}
		}

		if attempt < maxAttempts {
			colorPrint(
				fmt.Sprintf("⏳ Connection validation attempt %d/%d failed: %v. Retrying...", 
					attempt, maxAttempts, err),
				"yellow",
			)
			select {
			case <-time.After(baseDelay * time.Duration(attempt)):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, &DatabaseError{
		Operation: "connection",
		Detail:   fmt.Sprintf("failed after %d validation attempts", maxAttempts),
		Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Advice:   "Check database availability and network stability",
		Err:      err,
	}
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
			Detail:   fmt.Sprintf("failed to verify user %q", cfg.User),
			Target:   cfg.User,
			Advice:   "Check database permissions and connection",
			Err:      err,
		}
	}

	if !exists {
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), "green")
		sql := fmt.Sprintf(
			`CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
			parseUserFlags(cfg.UserFlags),
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user creation",
				Detail:   fmt.Sprintf("failed to create user %s", pgx.Identifier{cfg.User}.Sanitize()),
				Target:   cfg.User,
				Advice:   "Verify user creation privileges",
				Err:      err,
			}
		}
	} else {
		colorPrint(fmt.Sprintf("👤 Updating role %s...", cfg.User), "green")
		sql := fmt.Sprintf(
			`ALTER ROLE %s WITH ENCRYPTED PASSWORD %s %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
			parseUserFlags(cfg.UserFlags),
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user update",
				Detail:   fmt.Sprintf("failed to update role %s", pgx.Identifier{cfg.User}.Sanitize()),
				Target:   cfg.User,
				Advice:   "Check password requirements and user permissions",
				Err:      err,
			}
		}
	}

	return tx.Commit(ctx)
}

func parseUserFlags(flags string) string {
	var validFlags []string
	for _, flag := range strings.Fields(flags) {
		switch flag {
		case "--createdb", "--createrole", "--inherit", "--no-login", 
			"--replication", "--superuser", "--no-superuser":
			validFlags = append(validFlags, strings.TrimPrefix(flag, "--"))
		default:
			log.Printf("⚠️ Warning: Ignoring unsupported user flag: %s", flag)
		}
	}
	return strings.Join(validFlags, " ")
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
			Detail:   fmt.Sprintf("failed to verify database %q", cfg.DBName),
			Target:   cfg.DBName,
			Advice:   "Check database connection and permissions",
			Err:      err,
		}
	}

	if !exists {
		colorPrint(fmt.Sprintf("📦 Creating database %s...", cfg.DBName), "green")
		sql := fmt.Sprintf(
			`CREATE DATABASE %s OWNER %s`,
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize(),
		)

		if _, err = tx.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "database creation",
				Detail:   fmt.Sprintf("failed to create database %s", pgx.Identifier{cfg.DBName}.Sanitize()),
				Target:   cfg.DBName,
				Advice:   "Verify user has CREATEDB privilege",
				Err:      err,
			}
		}
	}

	colorPrint(fmt.Sprintf("🔑 Granting privileges on %q to %q...", cfg.DBName, cfg.User), "green")
	sql := fmt.Sprintf(
		`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`,
		pgx.Identifier{cfg.DBName}.Sanitize(),
		pgx.Identifier{cfg.User}.Sanitize(),
	)

	if _, err = tx.Exec(ctx, sql); err != nil {
		return &DatabaseError{
			Operation: "privileges assignment",
			Detail:   fmt.Sprintf("failed to grant privileges on %s", pgx.Identifier{cfg.DBName}.Sanitize()),
			Target:   cfg.DBName,
			Advice:   "Check user permissions and database ownership",
			Err:      err,
		}
	}

	return tx.Commit(ctx)
}

// ======================
// Main Application
// ======================

func main() {
	if err := run(); err != nil {
		colorPrint(err.Error(), "red")
		os.Exit(1)
	}
	colorPrint("✅ Database initialization completed successfully", "green")
}

func colorPrint(text, color string) {
	var colorCode string
	switch color {
	case "red":
		colorCode = "\033[31m"
	case "green":
		colorCode = "\033[32m"
	case "yellow":
		colorCode = "\033[33m"
	default:
		colorCode = "\033[0m"
	}
	fmt.Printf("%s%s\033[0m\n", colorCode, text)
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
        
	log.Printf("📋 Loaded configuration:\n%s", cfg.String())
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := createUser(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return err
	}

	return nil
}
