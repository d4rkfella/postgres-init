package main

import (
	"context"
	"crypto/tls"
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
	pgxssl "github.com/jackc/pgx/v5/pgxpool"
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

	// Validate passwords
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
				Err:      err,
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

	// Properly escape special characters
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
			Detail:   "invalid connection parameters",
			Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:   "Check special characters in credentials",
			Err:      err,
		}
	}

	// Configure TLS
	tlsConfig, err := createTLSConfig(cfg.SSLMode, cfg.SSLRootCert)
	if err != nil {
		return nil, err
	}
	parsedConfig.ConnConfig.TLSConfig = tlsConfig

	// Pool settings
	parsedConfig.MaxConns = 3
	parsedConfig.MinConns = 1
	parsedConfig.MaxConnLifetime = 5 * time.Minute
	parsedConfig.ConnConfig.ConnectTimeout = 10 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, parsedConfig)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "connection",
			Detail:   "failed to create connection pool",
			Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Advice:   "Verify network connectivity and credentials",
			Err:      err,
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

func createTLSConfig(sslMode, sslRootCert string) (*tls.Config, error) {
	if sslMode == "disable" {
		return nil, nil
	}

	sslConfig := &pgxssl.Config{
		TLSConfig: &tls.Config{},
	}

	switch sslMode {
	case "require":
		sslConfig.TLSConfig.InsecureSkipVerify = true
	case "verify-ca", "verify-full":
		if sslRootCert != "" {
			certBytes, err := os.ReadFile(sslRootCert)
			if err != nil {
				return nil, &DatabaseError{
					Operation: "ssl-config",
					Detail:   "failed to read SSL certificate",
					Target:   sslRootCert,
					Advice:   "Verify file permissions and path",
					Err:      err,
				}
			}
			sslConfig.TLSConfig.RootCAs = x509.NewCertPool()
			if ok := sslConfig.TLSConfig.RootCAs.AppendCertsFromPEM(certBytes); !ok {
				return nil, &DatabaseError{
					Operation: "ssl-config",
					Detail:   "failed to parse SSL certificate",
					Target:   sslRootCert,
					Advice:   "Verify certificate is in PEM format",
				}
			}
		}
		if sslMode == "verify-full" {
			sslConfig.TLSConfig.ServerName = os.Getenv("INIT_POSTGRES_HOST")
		}
	}

	return sslConfig.TLSConfig, nil
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var exists bool
	err = tx.QueryRow(ctx, 
		"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1", 
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

	flags, err := parseUserFlags(cfg.UserFlags)
	if err != nil {
		return &DatabaseError{
			Operation: "user-config",
			Detail:   "invalid user flags",
			Target:   cfg.UserFlags,
			Advice:   "Use supported role flags",
			Err:      err,
		}
	}

	if !exists {
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), "green")
		sql := fmt.Sprintf(
			`CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
			flags,
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
			flags,
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
	defer func() {
		pool.Close()
		log.Println("Closed database connection pool")
	}()

	if err := createUser(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return err
	}

	return nil
}
