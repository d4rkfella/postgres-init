package main

import (
	"context"
	"fmt"
	"os"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

const (
	Red     = "red"
	Green   = "green"
	Yellow  = "yellow"
	Default = "default"
)

type DatabaseError struct {
	Operation string
	Detail    string
	Err       error
}

func (e *DatabaseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Operation, e.Detail, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Operation, e.Detail)
}

func (e *DatabaseError) Unwrap() error {
	return e.Err
}

func main() {
	if err := run(); err != nil {
		colorPrint(fmt.Sprintf("❌ Error: %v", err), Red)
		os.Exit(1)
	}
	colorPrint("Database initialization completed successfully", Green)
}

func quoteLiteral(literal string) string {
	return "'" + strings.ReplaceAll(literal, "'", "''") + "'"
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration failed: %w", err)
	}

	ctx := context.Background()
	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := waitForPostgres(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createUser(ctx, pool, cfg); err != nil {
		return err
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return err
	}

	return nil
}

func loadConfig() (Config, error) {
	port, err := strconv.Atoi(getEnvWithDefault("INIT_POSTGRES_PORT", "5432"))
	if err != nil {
		return Config{}, &DatabaseError{
			Operation: "config",
			Detail:   "invalid port number",
			Err:      err,
		}
	}

	superUser, err := mustGetEnv("INIT_POSTGRES_SUPER_USER")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	superPass, err := mustGetEnv("INIT_POSTGRES_SUPER_PASS")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	user, err := mustGetEnv("INIT_POSTGRES_USER")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	userPass, err := mustGetEnv("INIT_POSTGRES_PASS")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	dbName, err := mustGetEnv("INIT_POSTGRES_DBNAME")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	host, err := mustGetEnv("INIT_POSTGRES_HOST")
	if err != nil {
		return Config{}, wrapEnvError(err)
	}

	return Config{
		Host:        host,
		Port:        port,
		SuperUser:   superUser,
		SuperPass:   superPass,
		User:        user,
		UserPass:    userPass,
		DBName:      dbName,
		UserFlags:   os.Getenv("INIT_POSTGRES_USER_FLAGS"),
		SSLMode:     getEnvWithDefault("INIT_POSTGRES_SSLMODE", "disable"),
		SSLRootCert: os.Getenv("INIT_POSTGRES_SSLROOTCERT"),
	}, nil
}

func wrapEnvError(err error) error {
	return &DatabaseError{
		Operation: "config",
		Detail:   "missing environment variable",
		Err:      err,
	}
}

func mustGetEnv(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return value, nil
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func connectPostgres(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(cfg.SuperUser), 
		url.QueryEscape(cfg.SuperPass),
		cfg.Host, 
		cfg.Port, 
		url.QueryEscape(cfg.SuperUser), 
		cfg.SSLMode)

	if (cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full") && cfg.SSLRootCert == "" {
		return nil, &DatabaseError{
			Operation: "SSL configuration",
			Detail:   fmt.Sprintf("SSL mode '%s' requires certificate", cfg.SSLMode),
		}
	}
	if cfg.SSLRootCert != "" {
		connStr += fmt.Sprintf("&sslrootcert=%s", url.QueryEscape(cfg.SSLRootCert))
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "connection setup",
			Detail:   fmt.Sprintf("invalid config for %s:%d", cfg.Host, cfg.Port),
			Err:      err,
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, &DatabaseError{
			Operation: "connection",
			Detail:   fmt.Sprintf("failed to connect as '%s'", cfg.SuperUser),
			Err:      err,
		}
	}

	return pool, nil
}

func waitForPostgres(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	const timeout = 30 * time.Second
	start := time.Now()

	for {
		if time.Since(start) > timeout {
			return &DatabaseError{
				Operation: "connection wait",
				Detail:   fmt.Sprintf("timeout after %v for %s:%d", timeout, cfg.Host, cfg.Port),
			}
		}

		err := pool.Ping(ctx)
		if err == nil {
			colorPrint(fmt.Sprintf("✅ Connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port), Green)
			return nil
		}

		colorPrint(fmt.Sprintf("⏳ Waiting for PostgreSQL at %s:%d...", cfg.Host, cfg.Port), Yellow)
		time.Sleep(1 * time.Second)
	}
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return &DatabaseError{
			Operation: "user check",
			Detail:   fmt.Sprintf("failed to verify user '%s'", cfg.User),
			Err:      err,
		}
	}

	if exists != 1 {
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), Green)
		sql := fmt.Sprintf(
			`CREATE ROLE %s LOGIN ENCRYPTED PASSWORD %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
		)
		
		if cfg.UserFlags != "" {
			flags := strings.Fields(cfg.UserFlags)
			for _, flag := range flags {
				switch flag {
				case "--createdb":
					sql += " CREATEDB"
				case "--createrole":
					sql += " CREATEROLE"
				case "--inherit":
					sql += " INHERIT"
				case "--no-login":
					sql += " NOLOGIN"
				case "--replication":
					sql += " REPLICATION"
				case "--superuser":
					sql += " SUPERUSER"
				case "--no-superuser":
					sql += " NOSUPERUSER"
				default:
					if strings.HasPrefix(flag, "--") {
						log.Printf("⚠️ Warning: Unsupported user flag: %s", flag)
					}
				}
			}
		}

		if _, err = pool.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user creation",
				Detail:   fmt.Sprintf("failed to create user %s", pgx.Identifier{cfg.User}.Sanitize()),
				Err:      err,
			}
		}
	} else {
		colorPrint(fmt.Sprintf("👤 Updating password for existing user %s...", cfg.User), Green)
		sql := fmt.Sprintf(
			`ALTER ROLE %s WITH ENCRYPTED PASSWORD %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
		)

		if _, err = pool.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user update",
				Detail:   fmt.Sprintf("failed to update user %s", pgx.Identifier{cfg.User}.Sanitize()),
				Err:      err,
			}
		}
	}
	return nil
}

func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", cfg.DBName).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return &DatabaseError{
			Operation: "database check",
			Detail:   fmt.Sprintf("failed to verify database '%s'", cfg.DBName),
			Err:      err,
		}
	}

	if exists != 1 {
		colorPrint(fmt.Sprintf("📦 Creating database %s...", cfg.DBName), Green)
		sql := fmt.Sprintf(
			`CREATE DATABASE %s OWNER %s`,
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize(),
		)
		if _, err = pool.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "database creation",
				Detail:   fmt.Sprintf("failed to create database %s", pgx.Identifier{cfg.DBName}.Sanitize()),
				Err:      err,
			}
		}
	}

	colorPrint(fmt.Sprintf("🔑 Granting privileges to user %q on database %q...", cfg.User, cfg.DBName), Green)
	sql := fmt.Sprintf(
		`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`,
		pgx.Identifier{cfg.DBName}.Sanitize(),
		pgx.Identifier{cfg.User}.Sanitize(),
	)
	if _, err = pool.Exec(ctx, sql); err != nil {
		return &DatabaseError{
			Operation: "privileges assignment",
			Detail:   fmt.Sprintf("failed to grant privileges on %s", pgx.Identifier{cfg.DBName}.Sanitize()),
			Err:      err,
		}
	}
	
	return nil
}

func colorPrint(text, color string) {
	var colorCode string
	switch color {
	case Red:
		colorCode = "\033[31m"
	case Green:
		colorCode = "\033[32m"
	case Yellow:
		colorCode = "\033[33m"
	default:
		colorCode = "\033[0m"
	}
	fmt.Printf("%s%s\033[0m\n", colorCode, text)
}
