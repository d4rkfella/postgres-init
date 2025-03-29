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

// Config struct for database initialization
type Config struct {
	Host       string
	SuperUser  string
	SuperPass  string
	User       string
	UserPass   string
	DBName     string
	Port       int
	UserFlags  string
	InitSQLDir string
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	// Connect to PostgreSQL
	pool := connectPostgres(ctx, cfg)
	defer pool.Close()

	// Wait for PostgreSQL to be ready
	waitForPostgres(ctx, pool, cfg)

	// Create user and database
	if err := createUser(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}
	if err := createDatabase(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	log.Println("✅ Database initialization completed successfully")
}

// Load configuration from environment variables
func loadConfig() Config {
	portStr := getEnvWithDefault("INIT_POSTGRES_PORT", "5432")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("❌ Invalid port number: %v", err)
	}

	return Config{
		Host:       mustGetEnv("INIT_POSTGRES_HOST"),
		SuperUser:  getEnvWithDefault("INIT_POSTGRES_SUPER_USER", "postgres"),
		SuperPass:  mustGetEnv("INIT_POSTGRES_SUPER_PASS"),
		User:       mustGetEnv("INIT_POSTGRES_USER"),
		UserPass:   mustGetEnv("INIT_POSTGRES_PASS"),
		DBName:     mustGetEnv("INIT_POSTGRES_DBNAME"),
		Port:       port,
		UserFlags:  os.Getenv("INIT_POSTGRES_USER_FLAGS"),
		InitSQLDir: getEnvWithDefault("INIT_POSTGRES_INIT_SQL_DIR", "/initdb"),
	}
}

// Get required environment variable or fail
func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("❌ Required environment variable %s is not set", key)
	}
	return value
}

// Get environment variable with default fallback
func getEnvWithDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// Connect to PostgreSQL using pgxpool
func connectPostgres(ctx context.Context, cfg Config) *pgxpool.Pool {
	// Escape credentials for special characters
	escapedUser := url.QueryEscape(cfg.SuperUser)
	escapedPass := url.QueryEscape(cfg.SuperPass)
	escapedDB := url.QueryEscape(cfg.SuperUser)

	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		escapedUser, escapedPass, cfg.Host, cfg.Port, escapedDB)

	log.Println("🔄 Connecting to PostgreSQL:", connStr)

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

// Wait for PostgreSQL to become ready
func waitForPostgres(ctx context.Context, pool *pgxpool.Pool, cfg Config) {
	start := time.Now()
	timeout := 30 * time.Second

	for {
		if time.Since(start) > timeout {
			log.Fatal("❌ Timeout waiting for PostgreSQL to become ready")
		}

		if err := pool.Ping(ctx); err == nil {
			log.Printf("✅ Connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port)
			break
		}

		log.Printf("⏳ Waiting for PostgreSQL (%s:%d)...", cfg.Host, cfg.Port)
		time.Sleep(2 * time.Second)
	}
}

// Create user if it does not exist
func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists bool
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("❌ Failed to check user existence: %w", err)
	}

	if !exists {
		log.Printf("🔧 Creating user %s...", cfg.User)

		sql := fmt.Sprintf("CREATE ROLE \"%s\" LOGIN PASSWORD '%s'", cfg.User, cfg.UserPass)
		if _, err = pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("❌ Failed to create user: %w", err)
		}
	}

	return nil
}

// Create database if it does not exist
func createDatabase(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists bool
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", cfg.DBName).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("❌ Failed to check database existence: %w", err)
	}

	if !exists {
		log.Printf("🔧 Creating database %s...", cfg.DBName)
		sql := fmt.Sprintf("CREATE DATABASE \"%s\" OWNER \"%s\"", cfg.DBName, cfg.User)
		if _, err = pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("❌ Failed to create database: %w", err)
		}
	}

	return nil
}
