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
\033[1;36m┌───────────────────────────────
│ \033[1;35mDatabase Configuration %s\033[1;36m
├───────────────────────────────
│ \033[1;34m%-15s\033[0m %-30q
│ \033[1;34m%-15s\033[0m %-30d
│ \033[1;34m%-15s\033[0m %-30q
│ \033[1;34m%-15s\033[0m %-30s
│ \033[1;34m%-15s\033[0m %s%-12s\033[0m %s
│ \033[1;34m%-15s\033[0m %-30q
\033[1;36m└───────────────────────────────\033[0m`,
		sslStatus,
		"Host:", c.Host,
		"Port:", c.Port,
		"SuperUser:", c.SuperUser,
		"Database:", c.DBName,
		"SSL Mode:", sslColor, c.SSLMode, sslStatus,
		"SSL Root Cert:", c.SSLRootCert,
	)
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

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		url.QueryEscape(cfg.SuperUser),
		url.QueryEscape(cfg.SuperPass),
		cfg.Host,
		cfg.Port,
		url.QueryEscape(cfg.SuperUser))

	parsedConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "configuration",
			Detail:    "invalid connection parameters",
			Target:    fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			Err:       err,
		}
	}

	parsedConfig.ConnConfig.TLSConfig = cfg.TLSConfig
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
			fmt.Printf("\033[33m⚠️ Closed connection pool due to initialization failure\033[0m\n")
		}
	}()

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = pool.Ping(ctx)
		if err == nil {
			fmt.Printf("\033[32m✅ Successfully connected to %s:%d\033[0m\n", cfg.Host, cfg.Port)

			if cfg.SSLMode != "disable" {
				conn, err := pool.Acquire(ctx)
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
					state := tlsConn.ConnectionState()
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
			} else {
				fmt.Printf("\n\033[33m⚠️  Connection is \033[1;31mUNENCRYPTED\033[0m\033[33m (SSL disabled)\033[0m\n")
			}

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
