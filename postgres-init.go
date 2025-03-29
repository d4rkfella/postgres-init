package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds the database configuration
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

func main() {
	cfg := loadConfig()
	
	// Only log the safe connection details
	log.Printf("🔄 Connecting to PostgreSQL with host=%s, port=%d, user=%s, sslmode=%s", 
		cfg.Host, cfg.Port, cfg.SuperUser, getEnvWithDefault("POSTGRES_SSL_MODE", "disable"))

	ctx := context.Background()
	pool := connectPostgres(ctx, cfg)
	defer pool.Close()

	waitForPostgres(ctx, pool, cfg)

	if err := createUser(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	if err := createDatabase(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	colorPrint("Database initialization completed successfully", "green")
}

// LoadConfig reads environment variables
func loadConfig() Config {
	port, err := strconv.Atoi(getEnvWithDefault("INIT_POSTGRES_PORT", "5432"))
	if err != nil {
		log.Fatalf("❌ Invalid port number: %v", err)
	}

	cfg := Config{
		Host:        mustGetEnv("INIT_POSTGRES_HOST"),
		Port:        port,
		SuperUser:   getEnvWithDefault("INIT_POSTGRES_SUPER_USER", "postgres"),
		SuperPass:   mustGetEnv("INIT_POSTGRES_SUPER_PASS"),
		User:        mustGetEnv("INIT_POSTGRES_USER"),
		UserPass:    mustGetEnv("INIT_POSTGRES_PASS"),
		DBName:      mustGetEnv("INIT_POSTGRES_DBNAME"),
		UserFlags:   os.Getenv("INIT_POSTGRES_USER_FLAGS"),
		SSLMode:     getEnvWithDefault("INIT_POSTGRES_SSLMODE", "disable"),
		SSLRootCert: os.Getenv("INIT_POSTGRES_SSLROOTCERT"),
	}
	return cfg
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("❌ Required environment variable %s is not set", key)
	}
	return value
}

func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func connectPostgres(ctx context.Context, cfg Config) *pgxpool.Pool {
	escapedUser := url.QueryEscape(cfg.SuperUser)
	escapedPass := url.QueryEscape(cfg.SuperPass)
	escapedDB := url.QueryEscape(cfg.SuperUser)

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		escapedUser, escapedPass, cfg.Host, cfg.Port, escapedDB, cfg.SSLMode)

	// Include SSL root cert if required
	if (cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full") && cfg.SSLRootCert != "" {
		connStr += fmt.Sprintf("&sslrootcert=%s", url.QueryEscape(cfg.SSLRootCert))
	} else if cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full" {
		log.Fatalf("❌ SSL mode %s requires INIT_POSTGRES_SSLROOTCERT to be set", cfg.SSLMode)
	}

	log.Println("🔄 Connecting to PostgreSQL with:", connStr)

	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		log.Fatalf("❌ Unable to parse connection config: %v", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("❌ Unable to connect to database: %v", err)
	}

	return pool
}

func waitForPostgres(ctx context.Context, pool *pgxpool.Pool, cfg Config) {
	start := time.Now()
	timeout := 30 * time.Second

	for {
		if time.Since(start) > timeout {
			log.Fatal("❌ Timeout waiting for PostgreSQL to become ready")
		}

		err := pool.Ping(ctx)
		if err == nil {
			colorPrint(fmt.Sprintf("✅ Connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port), "green")
			break
		}

		colorPrint(fmt.Sprintf("⏳ Waiting for PostgreSQL at %s:%d...", cfg.Host, cfg.Port), "yellow")
		time.Sleep(1 * time.Second)
	}
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int // Change from bool to int
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("⚠️ Failed to check user existence: %w", err)
	}

	if exists != 1 { // Check if the value returned is 1, meaning the user exists
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), "green")
		sql := fmt.Sprintf("CREATE ROLE \"%s\" LOGIN PASSWORD '%s'", cfg.User, cfg.UserPass)

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
			return fmt.Errorf("❌ Failed to create user: %w", err)
		}
	}
	return nil
}

func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists bool
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", cfg.DBName).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("⚠️ Failed to check database existence: %w", err)
	}

	if !exists {
		colorPrint(fmt.Sprintf("📦 Creating database %s...", cfg.DBName), "green")
		if _, err = pool.Exec(ctx, "CREATE DATABASE "+cfg.DBName+" OWNER "+cfg.User); err != nil {
			return fmt.Errorf("❌ Failed to create database: %w", err)
		}
	}

	colorPrint("🔑 Granting privileges to user on database...", "green")
	if _, err = pool.Exec(ctx, "GRANT ALL PRIVILEGES ON DATABASE "+cfg.DBName+" TO "+cfg.User); err != nil {
		return fmt.Errorf("❌ Failed to grant privileges: %w", err)
	}

	return nil
}

// colorPrint prints text with ANSI color codes
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
