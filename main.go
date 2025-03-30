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

func main() {
	if err := run(); err != nil {
		colorPrint(fmt.Sprintf("❌ Error: %v", err), Red)
		os.Exit(1)
	}

	colorPrint("Database initialization completed successfully", Green)
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	ctx := context.Background()
	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer pool.Close()

	if err := waitForPostgres(ctx, pool, cfg); err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	if err := createUser(ctx, pool, cfg); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		return fmt.Errorf("failed to create database: %w", err)
	}

	return nil
}

func loadConfig() (Config, error) {
	port, err := strconv.Atoi(getEnvWithDefault("INIT_POSTGRES_PORT", "5432"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid port number: %w", err)
	}

	superUser, err := mustGetEnv("INIT_POSTGRES_SUPER_USER")
	if err != nil {
		return Config{}, err
	}

	superPass, err := mustGetEnv("INIT_POSTGRES_SUPER_PASS")
	if err != nil {
		return Config{}, err
	}

	user, err := mustGetEnv("INIT_POSTGRES_USER")
	if err != nil {
		return Config{}, err
	}

	userPass, err := mustGetEnv("INIT_POSTGRES_PASS")
	if err != nil {
		return Config{}, err
	}

	dbName, err := mustGetEnv("INIT_POSTGRES_DBNAME")
	if err != nil {
		return Config{}, err
	}

	host, err := mustGetEnv("INIT_POSTGRES_HOST")
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
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
	}
	return cfg, nil
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
		url.QueryEscape(cfg.SuperUser), url.QueryEscape(cfg.SuperPass),
		cfg.Host, cfg.Port, url.QueryEscape(cfg.SuperUser), cfg.SSLMode)

	if (cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full") && cfg.SSLRootCert != "" {
		connStr += fmt.Sprintf("&sslrootcert=%s", url.QueryEscape(cfg.SSLRootCert))
	} else if cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full" {
		return nil, fmt.Errorf("SSL mode %s requires INIT_POSTGRES_SSLROOTCERT to be set", cfg.SSLMode)
	}

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to PostgreSQL: %w", err)
	}

	return pool, nil
}

func waitForPostgres(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	start := time.Now()
	timeout := 30 * time.Second

	for {
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout waiting for PostgreSQL to become ready")
		}

		err := pool.Ping(ctx)
		if err == nil {
			colorPrint(fmt.Sprintf("✅ Connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port), Green)
			break
		}

		colorPrint(fmt.Sprintf("⏳ Waiting for PostgreSQL at %s:%d...", cfg.Host, cfg.Port), Yellow)
		time.Sleep(1 * time.Second)
	}
	return nil
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int
	// Check if the user already exists
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)
	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("failed to check user existence: %w", err)
	}

	// If the user doesn't exist, create the user
	if exists != 1 {
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), Green)

		// SQL query with placeholders
		sql := `CREATE ROLE $1 LOGIN ENCRYPTED PASSWORD $2`
		args := []interface{}{cfg.User, cfg.UserPass}

		// Dynamically add flags to the SQL query
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
					log.Printf("⚠️ Warning: Unsupported user flag: %s", flag)
				}
			}
		}

		// Execute the SQL query with the parameters
		if err := execWithErrorHandling(ctx, pool, sql, args...); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	} else {
		// If the user exists, update the password
		colorPrint(fmt.Sprintf("👤 Updating password for existing user %s...", cfg.User), Green)
		sql := `ALTER ROLE $1 WITH ENCRYPTED PASSWORD $2`
		args := []interface{}{cfg.User, cfg.UserPass}

		if err := execWithErrorHandling(ctx, pool, sql, args...); err != nil {
			return fmt.Errorf("failed to update user password: %w", err)
		}
	}
	return nil
}

func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", cfg.DBName).Scan(&exists)
	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("failed to check database existence: %w", err)
	}

	if exists != 1 {
		colorPrint(fmt.Sprintf("📦 Creating database %s...", cfg.DBName), Green)
		sql := `CREATE DATABASE $1 OWNER $2`
		args := []interface{}{cfg.DBName, cfg.User}

		if err := execWithErrorHandling(ctx, pool, sql, args...); err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
	}

	colorPrint(fmt.Sprintf("🔑 Granting all privileges to user \"%s\" on database \"%s\"...", cfg.User, cfg.DBName), Green)
	sql := `GRANT ALL PRIVILEGES ON DATABASE $1 TO $2`
	args := []interface{}{cfg.DBName, cfg.User}

	if err := execWithErrorHandling(ctx, pool, sql, args...); err != nil {
		return fmt.Errorf("failed to grant privileges: %w", err)
	}

	return nil
}

func execWithErrorHandling(ctx context.Context, pool *pgxpool.Pool, sql string, args ...interface{}) error {
	log.Printf("Executing SQL: %s with args: %v", sql, args)

	_, err := pool.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("failed to execute SQL: %s, args: %v, error: %w", sql, args, err)
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
