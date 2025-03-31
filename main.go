package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
	TLSConfig   *tls.Config
}

// ======================
// Helper Functions
// ======================

func (c Config) String() string {
	sslColor := "\033[33m"
	sslStatus := "⚠️"
	if c.SSLMode == "verify-ca" || c.SSLMode == "verify-full" {
		sslColor = "\033[32m"
		sslStatus = "🔒"
	} else if c.SSLMode == "disable" {
		sslColor = "\033[31m"
		sslStatus = "⛔"
	}

	return fmt.Sprintf(`
\033[1;36m┌─────────────────────────────────────────
│ \033[1;34m%-14s\033[0m %-30s
│ \033[1;34m%-14s\033[0m %-30d
│ \033[1;34m%-14s\033[0m %-30q
│ \033[1;34m%-14s\033[0m %-30q
│ \033[1;34m%-14s\033[0m %s%-17s\033[0m %s
│ \033[1;34m%-14s\033[0m %-30q
\033[1;36m└─────────────────────────────────────────\033[0m`,
		"Host:", c.Host,
		"Port:", c.Port,
		"SuperUser:", c.SuperUser,
		"Database:", c.DBName,
		"SSL Mode:", sslColor, c.SSLMode, sslStatus,
		"SSL Root Cert:", c.SSLRootCert,
	)
}

func handleSuccessfulConnection(pool *pgxpool.Pool, cfg Config) (*pgxpool.Pool, error) {
	fmt.Printf("\033[32m✅ Successfully connected to %s:%d\033[0m\n", cfg.Host, cfg.Port)

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
	verifiedStatus := "⚠️ Unverified"
	if len(state.VerifiedChains) > 0 {
		switch {
		case cfg.SSLMode == "verify-full":
			if err := state.PeerCertificates[0].VerifyHostname(cfg.Host); err == nil {
				verifiedStatus = "✅ Full Verification (CA+Hostname)"
			} else {
				verifiedStatus = fmt.Sprintf("\033[31m⛔ Host mismatch: %v\033[0m", err)
			}
		case cfg.SSLMode == "verify-ca":
			verifiedStatus = "✅ CA Verified"
		default:
			verifiedStatus = "🔒 Encrypted (Basic TLS)"
		}
	} else if cfg.SSLMode == "require" {
		verifiedStatus = "🔒 Encrypted (No Validation)"
	}

	fmt.Printf("\n\033[36m🔐 SSL Connection State:\033[0m\n")
	fmt.Printf("├─ \033[1;34mStatus:\033[0m    %s\n", encryptionStatus(state))
	fmt.Printf("├─ \033[1;34mVersion:\033[0m   %s %s\n",
		tlsVersionToString(state.Version),
		versionSecurityStatus(state.Version))
	fmt.Printf("├─ \033[1;34mCipher:\033[0m   %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("╰─ \033[1;34mValidation:\033[0m %s\n\n", verifiedStatus)
}

func sanitizeError(err error, password string) string {
	msg := err.Error()
	return strings.ReplaceAll(msg, password, "*****")
}

func classifyPostgresError(err error, cfg Config, operation string) *DatabaseError {
    var pgErr *pgconn.PgError
    if !errors.As(err, &pgErr) {
        return nil
    }

    newDBError := func(op, detail, advice string) *DatabaseError {
        target := cfg.Host
        if op == "authentication" {
            target = fmt.Sprintf("%s@%s", cfg.SuperUser, target)
        } else if strings.Contains(op, "user") {
            target = cfg.User
        } else if strings.Contains(op, "database") {
            target = cfg.DBName
        }
        
        return &DatabaseError{
            Operation: op,
            Detail:    detail,
            Target:    target,
            Code:      pgErr.Code,
            Advice:    advice,
            Err:       err,
        }
    }

    switch operation {
    case "connection":
        return classifyConnectionError(pgErr, newDBError)
    case "user_management":
        return classifyUserError(pgErr, newDBError)
    case "database_management":
        return classifyDatabaseError(pgErr, newDBError)
    default:
        return newDBError(operation, pgErr.Message, 
            "Check PostgreSQL logs for detailed error information")
    }
}

func classifyConnectionError(pgErr *pgconn.PgError, newDBError func(op, detail, advice string) *DatabaseError) *DatabaseError {
    switch pgErr.Code {
    case "28P01":
        return newDBError("authentication", "invalid password", "Verify password matches the database user")
    case "28000":
        if strings.Contains(pgErr.Message, "pg_hba.conf") {
            if strings.Contains(pgErr.Message, "no encryption") {
                return newDBError("ssl_configuration", "server requires SSL connection", 
                    "Set SSLMode to 'require', 'verify-ca', or 'verify-full'")
            }
            return newDBError("authorization", "connection rejected by pg_hba.conf", 
                "Check PostgreSQL's pg_hba.conf file")
        }
        return newDBError("authentication", "invalid authorization", "Verify user exists and has proper privileges")
    case "08000", "08001", "08003", "08004", "08006", "08007":
        return newDBError("connection", "connection failed", 
            "Check network connectivity and database availability")
    case "57P03":
        return newDBError("connection", "database is starting up", "Wait for database to become ready")
    default:
        return nil
    }
}

func classifyUserError(pgErr *pgconn.PgError, newDBError func(op, detail, advice string) *DatabaseError) *DatabaseError {
    switch pgErr.Code {
    case "42710":
        return newDBError("user_creation", "database user already exists", 
            "Use a different username or set 'IF NOT EXISTS'")
    case "0LP01":
        return newDBError("user_configuration", "invalid user configuration", 
            "Check password complexity rules and connection limit settings")
    case "42501":
        return newDBError("privileges", "insufficient privileges for user operation", 
            "Use a superuser account or request proper privileges")
    default:
        return nil
    }
}

func classifyDatabaseError(pgErr *pgconn.PgError, newDBError func(op, detail, advice string) *DatabaseError) *DatabaseError {
    switch pgErr.Code {
    case "42P04":
        return newDBError("database_creation", "database already exists", 
            "Use a different database name or set 'IF NOT EXISTS'")
    case "42501":
        return newDBError("privileges", "insufficient privileges to create database", 
            "Use a superuser account or request CREATEDB privileges")
    case "3D000":
        return newDBError("database_access", "database does not exist", 
            "Verify database name or create it first")
    default:
        return nil
    }
}

func isFatalError(operation string) bool {
	return operation == "authentication" || operation == "ssl_configuration"
}

func validatePassword(pass string) error {
	if len(pass) < 12 {
		return fmt.Errorf("minimum 12 characters required")
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

func encryptionStatus(state tls.ConnectionState) string {
	if state.HandshakeComplete {
		return "\033[32mENCRYPTED\033[0m"
	}
	return "\033[31mUNENCRYPTED\033[0m"
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
		return fmt.Sprintf("0x%04X", version)
	}
}

func versionSecurityStatus(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "\033[32m(Secure)\033[0m"
	case tls.VersionTLS12:
		return "\033[33m(Adequate)\033[0m"
	default:
		return "\033[31m(Insecure)\033[0m"
	}
}

func parseUserFlags(flags string) (string, error) {
	validFlags := make([]string, 0)
	allowedFlags := map[string]bool{
		// Boolean privileges
		"--login":          true, // LOGIN
		"--no-login":       true, // NOLOGIN
		"--createdb":       true, // CREATEDB
		"--no-createdb":    true, // NOCREATEDB
		"--createrole":     true, // CREATEROLE
		"--no-createrole":  true, // NOCREATEROLE
		"--inherit":        true, // INHERIT
		"--no-inherit":     true, // NOINHERIT
		"--replication":    true, // REPLICATION
		"--no-replication": true, // NOREPLICATION
		"--superuser":      true, // SUPERUSER
		"--no-superuser":   true, // NOSUPERUSER
		"--bypassrls":      true, // BYPASSRLS (PostgreSQL 9.5+)
		"--no-bypassrls":   true, // NOBYPASSRLS

		// Connection limits
		"--connection-limit": true, // Needs separate value handling
	}

	for _, flag := range strings.Fields(flags) {
		parts := strings.SplitN(flag, "=", 2)
		baseFlag := parts[0]

		if !allowedFlags[baseFlag] {
			return "", fmt.Errorf("unsupported user flag: %s", baseFlag)
		}

		// Handle connection limit separately
		if baseFlag == "--connection-limit" {
			if len(parts) != 2 {
				return "", fmt.Errorf("connection limit requires a value")
			}
			validFlags = append(validFlags, fmt.Sprintf("CONNECTION LIMIT %s", parts[1]))
			continue
		}

		// Convert flags to PostgreSQL keywords
		pgFlag := strings.ToUpper(strings.TrimPrefix(baseFlag, "--"))
		pgFlag = strings.ReplaceAll(pgFlag, "-", " ")
		validFlags = append(validFlags, pgFlag)
	}

	return strings.Join(validFlags, " "), nil
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

	tlsConfig, err := createTLSConfig(cfg.SSLMode, cfg.SSLRootCert, cfg.Host)
	if err != nil {
		return Config{}, err
	}
	cfg.TLSConfig = tlsConfig

	return cfg, nil
}

func createTLSConfig(sslMode, sslRootCert, host string) (*tls.Config, error) {
	allowedModes := map[string]bool{
		"disable": true, "allow": true, "prefer": true,
		"require": true, "verify-ca": true, "verify-full": true,
	}

	if !allowedModes[sslMode] {
		return nil, &ConfigError{
			Operation: "ssl-config",
			Variable:  "INIT_POSTGRES_SSLMODE",
			Detail:    "invalid SSL mode",
			Expected:  "one of: disable, allow, prefer, require, verify-ca, verify-full",
		}
	}

	if sslMode == "disable" {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: sslMode == "require",
	}

	if sslMode == "verify-ca" || sslMode == "verify-full" {
		if sslRootCert == "" {
			return nil, &ConfigError{
				Operation: "ssl-config",
				Variable:  "INIT_POSTGRES_SSLROOTCERT",
				Detail:    "CA certificate required",
				Expected:  "path to root CA certificate",
			}
		}

		if _, err := os.Stat(sslRootCert); err != nil {
			return nil, &ConfigError{
				Operation: "ssl-config",
				Variable:  "INIT_POSTGRES_SSLROOTCERT",
				Detail:    "CA certificate file not found",
				Expected:  "valid path to CA certificate file",
				Err:       err,
			}
		}

		certBytes, err := os.ReadFile(sslRootCert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}

		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(certBytes) {
			return nil, &ConfigError{
				Operation: "ssl-config",
				Variable:  "INIT_POSTGRES_SSLROOTCERT",
				Detail:    "failed to parse CA certificates",
				Expected:  "PEM-encoded X.509 certificate(s)",
			}
		}

		if sslMode == "verify-full" {
			tlsConfig.ServerName = host
		}
	}

	return tlsConfig, nil
}

// ======================
// Database Operations
// ======================

func connectPostgres(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
    const maxAttempts = 30
    const baseDelay = 1 * time.Second

    connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
        url.QueryEscape(cfg.SuperUser),
        url.QueryEscape(cfg.SuperPass),
        cfg.Host,
        cfg.Port,
        url.QueryEscape(cfg.DBName),
        url.QueryEscape(cfg.SSLMode))

    parsedConfig, err := pgxpool.ParseConfig(connStr)
    if err != nil {
        return nil, classifyPostgresError(err, cfg, "connection")
    }

    if cfg.SSLMode != "disable" {
        parsedConfig.ConnConfig.TLSConfig = cfg.TLSConfig
    }

    parsedConfig.MaxConns = 3
    parsedConfig.MinConns = 1
    parsedConfig.MaxConnLifetime = 5 * time.Minute
    parsedConfig.ConnConfig.ConnectTimeout = 10 * time.Second

    pool, err := pgxpool.NewWithConfig(ctx, parsedConfig)
    if err != nil {
        return nil, classifyPostgresError(err, cfg, "connection")
    }

    defer func() {
        if err != nil {
            pool.Close()
            fmt.Printf("\033[33m⚠️ Closed connection pool due to initialization failure\033[0m\n")
        }
    }()

    for attempt := 1; attempt <= maxAttempts; attempt++ {
        err = pool.Ping(ctx)
        if err == nil {
            return handleSuccessfulConnection(pool, cfg)
        }

        if dbErr := classifyPostgresError(err, cfg, "connection"); dbErr != nil {
            if isFatalError(dbErr.Operation) {
                return nil, dbErr
            }
        }

        if attempt < maxAttempts {
            fmt.Printf("\033[33m⏳ Connection attempt %d/%d failed: %v. Retrying...\033[0m\n",
                attempt, maxAttempts, sanitizeError(err, cfg.SuperPass))
            select {
            case <-time.After(baseDelay * time.Duration(attempt)):
            case <-ctx.Done():
                return nil, classifyPostgresError(ctx.Err(), cfg, "connection")
            }
        }
    }

    return nil, classifyPostgresError(
        fmt.Errorf("failed after %d attempts", maxAttempts),
        cfg,
        "connection",
    )
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
    tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
    if err != nil {
        return classifyPostgresError(err, cfg, "user_management")
    }
    defer tx.Rollback(ctx)

    var exists bool
    err = tx.QueryRow(ctx,
        "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)",
        cfg.User,
    ).Scan(&exists)

    if err != nil {
        return classifyPostgresError(err, cfg, "user_management")
    }

    flags, err := parseUserFlags(cfg.UserFlags)
    if err != nil {
        return &DatabaseError{
            Operation: "user_configuration",
            Detail:    fmt.Sprintf("invalid flags: %v", err),
            Target:    cfg.UserFlags,
            Advice:    "Use valid --createdb, --createrole flags",
            Err:       err,
        }
    }

    op := "user_creation"
    sql := fmt.Sprintf("CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s %s",
        pgx.Identifier{cfg.User}.Sanitize(),
        quoteLiteral(cfg.UserPass),
        flags)

    if exists {
        op = "user_update"
        sql = fmt.Sprintf("ALTER ROLE %s WITH ENCRYPTED PASSWORD %s %s",
            pgx.Identifier{cfg.User}.Sanitize(),
            quoteLiteral(cfg.UserPass),
            flags)
    }

    if _, err = tx.Exec(ctx, sql); err != nil {
        return classifyPostgresError(err, cfg, op)
    }

    if err = tx.Commit(ctx); err != nil {
        return classifyPostgresError(err, cfg, "transaction")
    }

    return nil
}

func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
    tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
    if err != nil {
        return classifyPostgresError(err, cfg, "database_management")
    }
    defer tx.Rollback(ctx)

    var exists bool
    err = tx.QueryRow(ctx,
        "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)",
        cfg.DBName,
    ).Scan(&exists)

    if err != nil {
        return classifyPostgresError(err, cfg, "database_management")
    }

    if !exists {
        sql := fmt.Sprintf("CREATE DATABASE %s OWNER %s",
            pgx.Identifier{cfg.DBName}.Sanitize(),
            pgx.Identifier{cfg.User}.Sanitize())

        if _, err = tx.Exec(ctx, sql); err != nil {
            return classifyPostgresError(err, cfg, "database_creation")
        }
    }

    sql := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s",
        pgx.Identifier{cfg.DBName}.Sanitize(),
        pgx.Identifier{cfg.User}.Sanitize())

    if _, err = tx.Exec(ctx, sql); err != nil {
        return classifyPostgresError(err, cfg, "privileges_assignment")
    }

    if err = tx.Commit(ctx); err != nil {
        return classifyPostgresError(err, cfg, "transaction")
    }

    return nil
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

	fmt.Printf("\n\033[1;35m📋 Loaded Configuration\033[0m\n%s", cfg.String())

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
