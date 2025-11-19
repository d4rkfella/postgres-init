package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"os"
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
	Port        string
	SuperUser   string
	SuperPass   string
	User        string
	UserPass    string
	DBName      string
	UserFlags   string
	SSLMode     string
	SSLRootCert string
}

type DBHandle interface {
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Ping(context.Context) error
	Close()
}

// ======================
// Helper Functions
// ======================

func (c Config) String() string {
	sslColor := "\033[33m"
	sslStatus := "⚠️"
	switch c.SSLMode {
	case "verify-ca", "verify-full":
		sslColor = "\033[32m"
		sslStatus = "🔒"
	case "disable":
		sslColor = "\033[31m"
		sslStatus = "⛔"
	}

	return fmt.Sprintf(
		"\n\033[1;36m┌─────────────────────────────────────────\n"+
			"│ \033[1;34m%-14s\033[0m %-30s\n"+
			"│ \033[1;34m%-14s\033[0m %-30s\n"+
			"│ \033[1;34m%-14s\033[0m %-30q\n"+
			"│ \033[1;34m%-14s\033[0m %-30q\n"+
			"│ \033[1;34m%-14s\033[0m %s%-17s\033[0m %s\n"+
			"│ \033[1;34m%-14s\033[0m %-30q\n"+
			"\033[1;36m└─────────────────────────────────────────\033[0m",
		"Host:", c.Host,
		"Port:", c.Port,
		"SuperUser:", c.SuperUser,
		"Database:", c.DBName,
		"SSL Mode:", sslColor, c.SSLMode, sslStatus,
		"SSL Root Cert:", c.SSLRootCert,
	)
}

func handleSuccessfulConnection(pool *pgxpool.Pool, cfg Config) (*pgxpool.Pool, error) {
	fmt.Printf("\033[32m✅ Successfully connected to %s:%s\033[0m\n", cfg.Host, cfg.Port)

	if cfg.SSLMode != "disable" {
		conn, err := pool.Acquire(context.Background())
		if err != nil {
			return nil, &DatabaseError{
				Operation: "ssl-check",
				Detail:    "failed to acquire connection for SSL verification",
				Target:    cfg.Host,
				Advice:    "Check connection pool health",
				Err:       err,
			}
		}
		defer conn.Release()

		if tlsConn, ok := conn.Conn().PgConn().Conn().(*tls.Conn); ok {
			printSSLInfo(tlsConn.ConnectionState(), cfg)
		}
	} else {
		fmt.Printf("\n\033[33m⚠️  Connection is \033[1;31mUNENCRYPTED\033[0m\033[33m (SSL disabled)\033[0m\n")
	}

	return pool, nil
}

func printSSLInfo(state tls.ConnectionState, cfg Config) {
	fmt.Printf("\n\033[36m🔐 SSL Connection State:\033[0m\n")
	fmt.Printf("├─ \033[1;34mStatus:\033[0m    \033[32mENCRYPTED\033[0m\n")
	fmt.Printf("├─ \033[1;34mVersion:\033[0m   %s %s\n",
		tlsVersionToString(state.Version),
		versionSecurityStatus(state.Version))
	fmt.Printf("├─ \033[1;34mCipher:\033[0m   %s\n", tls.CipherSuiteName(state.CipherSuite))

	var verifiedStatus string
	switch {
	case len(state.VerifiedChains) > 0 && cfg.SSLMode == "verify-full":
		if err := state.PeerCertificates[0].VerifyHostname(cfg.Host); err == nil {
			verifiedStatus = "✅ Full Verification (CA+Hostname)"
		} else {
			verifiedStatus = fmt.Sprintf("⛔ Host mismatch: %v", err)
		}

	case len(state.VerifiedChains) > 0:
		verifiedStatus = "✅ CA Verified"

	default:
		verifiedStatus = "🔒 Encrypted (No Validation)"
	}

	fmt.Printf("╰─ \033[1;34mValidation:\033[0m %s\n\n", verifiedStatus)
}

func classifyPostgresError(err error, cfg Config, operation string) *DatabaseError {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return &DatabaseError{
			Operation: operation,
			Detail:    fmt.Sprintf("non-PostgreSQL error: %v", err),
			Target:    cfg.Host,
			Code:      "UNKNOWN",
			Advice:    "Check the error details and system logs",
			Err:       err,
		}
	}

	target := cfg.Host
	switch {
	case operation == "authentication":
		target = fmt.Sprintf("%s@%s", cfg.SuperUser, target)
	case strings.Contains(operation, "user"):
		target = cfg.User
	case strings.Contains(operation, "database"):
		target = cfg.DBName
	}

	var detail, advice string
	switch operation {
	case "connection":
		switch pgErr.Code {
		case "28P01":
			detail = fmt.Sprintf("invalid password (SQLSTATE %s)", pgErr.Code)
			advice = "Verify password matches the database user"
		case "28000":
			msg := strings.TrimSpace(pgErr.Message)
			if msg == "SSL off" || msg == "must be SSL" || msg == "server requires SSL" {
				detail = fmt.Sprintf("server requires SSL connection (SQLSTATE %s)", pgErr.Code)
				advice = "Set SSLMode to 'require', 'verify-ca', or 'verify-full'"
			} else {
				detail = fmt.Sprintf("connection rejected by pg_hba.conf (SQLSTATE %s)", pgErr.Code)
				advice = "Check PostgreSQL's pg_hba.conf file"
			}
		default:
			detail = fmt.Sprintf("connection failed (SQLSTATE %s)", pgErr.Code)
			advice = "Check network connectivity and database availability"
		}
	case "user_management":
		switch pgErr.Code {
		case "42710":
			detail = fmt.Sprintf("role already exists (SQLSTATE %s)", pgErr.Code)
			advice = "Use a different username or set 'IF NOT EXISTS'"
		case "42501":
			detail = fmt.Sprintf("insufficient privileges for user operation (SQLSTATE %s)", pgErr.Code)
			advice = "Use a superuser account or request proper privileges"
		default:
			detail = fmt.Sprintf("user management operation failed (SQLSTATE %s)", pgErr.Code)
			advice = fmt.Sprintf("Check PostgreSQL error code: %s", pgErr.Code)
		}
	case "database_management", "database_creation", "privileges_assignment":
		switch pgErr.Code {
		case "42P04":
			detail = fmt.Sprintf("database already exists (SQLSTATE %s)", pgErr.Code)
			advice = "Use a different database name or set 'IF NOT EXISTS'"
		case "42501":
			detail = fmt.Sprintf("insufficient privileges to create database (SQLSTATE %s)", pgErr.Code)
			advice = "Use a superuser account or request CREATEDB privileges"
		case "3D000":
			detail = fmt.Sprintf("database does not exist (SQLSTATE %s)", pgErr.Code)
			advice = "Verify database name or create it first"
		default:
			detail = fmt.Sprintf("database management operation failed (SQLSTATE %s)", pgErr.Code)
			advice = fmt.Sprintf("Check PostgreSQL error code: %s", pgErr.Code)
		}
	default:
		detail = fmt.Sprintf("unhandled operation type: %s (SQLSTATE %s)", operation, pgErr.Code)
		advice = "Contact system administrator"
	}

	return &DatabaseError{
		Operation: operation,
		Detail:    detail,
		Target:    target,
		Code:      pgErr.Code,
		Advice:    advice,
		Err:       err,
	}
}

func isFatalError(operation string) bool {
	return operation == "authentication" || operation == "ssl_configuration"
}

func validatePassword(pass string) error {
	policy := getDefaultPasswordPolicy()
	
	if len(pass) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	if policy.RequireUpper {
		if !strings.ContainsAny(pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return fmt.Errorf("password must contain at least one uppercase letter")
		}
	}

	if policy.RequireLower {
		if !strings.ContainsAny(pass, "abcdefghijklmnopqrstuvwxyz") {
			return fmt.Errorf("password must contain at least one lowercase letter")
		}
	}

	if policy.RequireNumber {
		if !strings.ContainsAny(pass, "0123456789") {
			return fmt.Errorf("password must contain at least one number")
		}
	}

	if policy.RequireSpecial {
		if !strings.ContainsAny(pass, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
			return fmt.Errorf("password must contain at least one special character")
		}
	}

	return nil
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func highlight(s string) string {
	return fmt.Sprintf("\033[1;36m%s\033[0m", s)
}

func redactString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) == 1 {
		return "*"
	}
	return string(s[0]) + strings.Repeat("*", len(s)-1)
}

func extractSQLState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func quoteLiteral(literal string) string {
	return "'" + strings.ReplaceAll(literal, "'", "''") + "'"
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "unknown"
	}
}

func versionSecurityStatus(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "(\033[32mSECURE\033[0m)"
	case tls.VersionTLS12:
		return "(\033[33mOK\033[0m)"
	case tls.VersionTLS10, tls.VersionTLS11:
		return "(\033[31mINSECURE\033[0m)"
	default:
		return ""
	}
}

func parseUserFlags(flags string) (string, error) {
	if flags == "" {
		return "", nil
	}
	
	validFlags := make([]string, 0)
	allowedFlags := map[string]bool{
		"LOGIN":       true,
		"NOLOGIN":     true,
		"CREATEDB":    true,
		"NOCREATEDB":  true,
		"CREATEROLE":  true,
		"NOCREATEROLE":true,
		"INHERIT":     true,
		"NOINHERIT":   true,
		"REPLICATION": true,
		"NOREPLICATION": true,
		"SUPERUSER":   true,
		"NOSUPERUSER": true,
		"BYPASSRLS":   true,
		"NOBYPASSRLS": true,
	}

	for _, flag := range strings.Split(flags, ",") {
		trimmedFlag := strings.TrimSpace(flag)
		if !allowedFlags[trimmedFlag] {
			return "", fmt.Errorf("unsupported user flag: %s", trimmedFlag)
		}
		validFlags = append(validFlags, trimmedFlag)
	}

	return strings.Join(validFlags, " "), nil
}

// ======================
// Configuration Loading
// ======================

type PasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSpecial bool
}

func getDefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:     12,
		RequireUpper:  true,
		RequireLower:  true,
		RequireNumber: true,
		RequireSpecial: true,
	}
}

func validateSSLConfig(cfg Config) error {
	switch cfg.SSLMode {
	case "disable", "require":
		return nil
	case "verify-ca", "verify-full":
		if cfg.SSLRootCert == "" {
			return &ConfigError{
				Operation: "ssl_configuration",
				Variable:  "POSTGRES_SSL_ROOTCERT_PATH",
				Detail:    "SSL root certificate path is required for SSL mode " + cfg.SSLMode,
				Expected:  "path to SSL root certificate file",
			}
		}
		if _, err := os.Stat(cfg.SSLRootCert); err != nil {
			return &ConfigError{
				Operation: "ssl_configuration",
				Variable:  "POSTGRES_SSL_ROOTCERT_PATH",
				Detail:    fmt.Sprintf("SSL root certificate file not found: %v", err),
				Expected:  "valid path to SSL root certificate file",
			}
		}
		return nil
	default:
		return &ConfigError{
			Operation: "ssl_configuration",
			Variable:  "POSTGRES_SSL_MODE",
			Detail:    "invalid SSL mode: " + cfg.SSLMode,
			Expected:  "one of: disable, require, verify-ca, verify-full",
		}
	}
}

func loadConfig() (Config, error) {
	var cfg Config

	required := map[string]*string{
		"POSTGRES_SUPER_USER": &cfg.SuperUser,
		"POSTGRES_SUPER_PASS": &cfg.SuperPass,
		"POSTGRES_USER":       &cfg.User,
		"POSTGRES_PASS":       &cfg.UserPass,
		"POSTGRES_DBNAME":     &cfg.DBName,
		"POSTGRES_HOST":       &cfg.Host,
	}

	for key, ptr := range required {
		*ptr = os.Getenv(key)
		if *ptr == "" {
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
			Variable:  "POSTGRES_SUPERPASS",
			Detail:    "failed to validate superuser password",
			Expected:  err.Error(),
			Err:       err,
		}
	}

	if err := validatePassword(cfg.UserPass); err != nil {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "POSTGRES_USER_PASSWORD",
			Detail:    "failed to validate application user password",
			Expected:  err.Error(),
			Err:       err,
		}
	}

	cfg.Port = getEnvWithDefault("POSTGRES_PORT", "5432")
	parsedFlags, err := parseUserFlags(getEnvWithDefault("POSTGRES_USER_FLAGS", ""))
	if err != nil {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "POSTGRES_USER_FLAGS",
			Detail:    "invalid user flags provided",
			Expected:  "a comma-separated list of valid flags (e.g., CREATEDB,LOGIN)",
			Err:       err,
		}
	}
	cfg.UserFlags = parsedFlags
	cfg.SSLMode = getEnvWithDefault("POSTGRES_SSLMODE", "disable")
	cfg.SSLRootCert = os.Getenv("POSTGRES_SSL_ROOTCERT_PATH")

	if err := validateSSLConfig(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// ======================
// Database Operations
// ======================

type PoolConfig struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	ConnectTimeout  time.Duration
}

func getDefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:        3,
		MinConns:        1,
		MaxConnLifetime: 5 * time.Minute,
		ConnectTimeout:  10 * time.Second,
	}
}

func connectPostgres(ctx context.Context, cfg Config) (DBHandle, error) {
	const maxAttempts = 10
	const baseDelay = 1 * time.Second

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s&sslrootcert=%s",
		url.QueryEscape(cfg.SuperUser),
		url.QueryEscape(cfg.SuperPass),
		cfg.Host,
		cfg.Port,
		url.QueryEscape(cfg.SuperUser),
		cfg.SSLMode,
		url.QueryEscape(cfg.SSLRootCert))

	parsedConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, &ConfigError{
			Operation: "connection string",
			Detail:    "error when parsing the connection string (check detailed error message below)",
			Expected:  "valid PostgreSQL connection string",
			Err:       err,
		}
	}

	poolCfg := getDefaultPoolConfig()
	parsedConfig.MaxConns = poolCfg.MaxConns
	parsedConfig.MinConns = poolCfg.MinConns
	parsedConfig.MaxConnLifetime = poolCfg.MaxConnLifetime
	parsedConfig.ConnConfig.ConnectTimeout = poolCfg.ConnectTimeout

	parsedConfig.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, parsedConfig)
	if err != nil {
		if dbErr := classifyPostgresError(err, cfg, "connection"); dbErr != nil {
			if dbErr.Code == "28P01" || dbErr.Code == "28000" {
				return nil, dbErr
			}
		}
		return nil, classifyPostgresError(err, cfg, "connection")
	}

	defer func() {
		if err != nil {
			pool.Close()
			fmt.Printf("\033[33m⚠️ Closed connection pool due to initialization failure\033[0m\n")
		}
	}()

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = pool.Ping(ctx)
		if err == nil {
			return handleSuccessfulConnection(pool, cfg)
		}

		if dbErr := classifyPostgresError(err, cfg, "connection"); dbErr != nil {
			if dbErr.Code == "28P01" || dbErr.Code == "28000" {
				return nil, dbErr
			}
			lastErr = dbErr
		} else {
			lastErr = err
		}

		if attempt < maxAttempts {
			fmt.Printf("\033[33m⏳ Connection attempt %d/%d failed: %v. Retrying...\033[0m\n",
				attempt, maxAttempts, lastErr)

			select {
			case <-time.After(baseDelay * time.Duration(attempt)):
			case <-ctx.Done():
				ctxErr := fmt.Errorf("context cancelled: %w", ctx.Err())
				combinedErr := fmt.Errorf("%v (last error: %w)", ctxErr, lastErr)
				return nil, combinedErr
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed after %d attempts: %w", maxAttempts, lastErr)
	}

	return nil, fmt.Errorf("unexpected error: no error but no successful connection")
}

func executeInTransaction(ctx context.Context, pool DBHandle, operation string, fn func(tx pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable,
	})
	if err != nil {
		return &DatabaseError{
			Operation: operation,
			Detail:    "failed to begin transaction",
			Advice:    "Check database connection and permissions",
			Err:       err,
		}
	}

	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
				fmt.Printf("\033[33m⚠️ Failed to rollback transaction: %v\033[0m\n", err)
			}
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return &DatabaseError{
			Operation: operation,
			Detail:    "failed to commit transaction",
			Advice:    "Check database connection and permissions",
			Err:       err,
		}
	}
	committed = true

	return nil
}

func createUser(ctx context.Context, pool DBHandle, cfg Config) error {
	if _, err := parseUserFlags(cfg.UserFlags); err != nil {
		return &DatabaseError{
			Operation: "user_validation",
			Detail:    "invalid user flags",
			Target:    cfg.User,
			Advice:    "Use valid flags: CREATEDB, CREATEROLE, LOGIN, SUPERUSER",
			Err:       err,
		}
	}

	return executeInTransaction(ctx, pool, "user_management", func(tx pgx.Tx) error {
		var exists bool
		err := tx.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)",
			cfg.User,
		).Scan(&exists)

		if err != nil {
			return &DatabaseError{
				Operation: "user_management",
				Detail:    "failed to check if user exists",
				Target:    cfg.User,
				Advice:    "Check database connection and permissions",
				Err:       err,
			}
		}

		var sql string
		var op string

		if exists {
			fmt.Printf("\033[32m👤 Updating role %s...\033[0m\n", highlight(cfg.User))
			op = "user_update"
			sql = fmt.Sprintf("ALTER ROLE %s WITH ENCRYPTED PASSWORD %s %s",
				pgx.Identifier{cfg.User}.Sanitize(),
				quoteLiteral(cfg.UserPass),
				cfg.UserFlags)
		} else {
			fmt.Printf("\033[32m👤 Creating user %s...\033[0m\n", highlight(cfg.User))
			op = "user_creation"
			sql = fmt.Sprintf("CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s %s",
				pgx.Identifier{cfg.User}.Sanitize(),
				quoteLiteral(cfg.UserPass),
				cfg.UserFlags)
		}

		if _, err = tx.Exec(ctx, sql); err != nil {
			return classifyPostgresError(err, cfg, op)
		}

		return nil
	})
}

func createDatabase(ctx context.Context, pool DBHandle, cfg Config) error {
	var exists bool
	err := pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
		cfg.DBName,
	).Scan(&exists)
	if err != nil {
		return &DatabaseError{
			Operation: "database_management",
			Detail:    "failed to check if database exists",
			Target:    cfg.DBName,
			Advice:    "Check database connection and permissions",
			Err:       err,
		}
	}

	if !exists {
		fmt.Printf("\033[32m📦 Creating database %s...\033[0m\n", highlight(cfg.DBName))
		sql := fmt.Sprintf("CREATE DATABASE %s OWNER %s",
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize())

		_, err = pool.Exec(ctx, sql)
		if err != nil {
			return classifyPostgresError(err, cfg, "database_creation")
		}
	}

	return executeInTransaction(ctx, pool, "privileges_assignment", func(tx pgx.Tx) error {
		fmt.Printf("\033[32m🔑 Granting privileges on %q to %q...\033[0m\n", cfg.DBName, cfg.User)
		sql := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s",
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize())

		if _, err = tx.Exec(ctx, sql); err != nil {
			return classifyPostgresError(err, cfg, "privileges_assignment")
		}

		return nil
	})
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

	fmt.Printf("\n\033[1;35m📋 Loaded Configuration\033[0m\n%s\n", cfg.String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		pool.Close()
		fmt.Printf("\n\033[36m🔌 Closed database connection pool\033[0m\n")
	}()

	if err := createUser(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return err
	}

	return nil
}
