package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	Host        string
	SuperUser   string
	SuperPass   string
	User        string
	UserPass    string
	DBName      string
	Port        int      // Changed from string to int
	UserFlags   string
	InitSQLDir  string
}

func main() {
	cfg := loadConfig()
	
	ctx := context.Background()
	pool := connectPostgres(ctx, cfg)
	defer pool.Close()

	waitForPostgres(ctx, pool, cfg)

	if err := createUser(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	if err := updateUserPassword(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	if err := processDatabases(ctx, pool, cfg); err != nil {
		log.Fatal(err)
	}

	colorPrint("Database initialization completed successfully", "green")
}

func loadConfig() Config {
	portStr := getEnvWithDefault("INIT_POSTGRES_PORT", "5432")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid port number: %v", err)
	}

	cfg := Config{
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
	return cfg
}

func mustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Required environment variable %s is not set", key)
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
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		log.Fatalf("Unable to parse connection config: %v", err)
	}

	config.ConnConfig.Host = cfg.Host
	config.ConnConfig.Port = uint16(cfg.Port)
	config.ConnConfig.User = cfg.SuperUser
	config.ConnConfig.Password = cfg.SuperPass
	config.ConnConfig.Database = cfg.SuperUser

	// Configure pool settings
	config.MaxConns = 5
	config.MinConns = 1
	config.HealthCheckPeriod = time.Minute
	config.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v", err)
	}

	return pool
}

func waitForPostgres(ctx context.Context, pool *pgxpool.Pool, cfg Config) {
	start := time.Now()
	timeout := 30 * time.Second
	
	for {
		if time.Since(start) > timeout {
			log.Fatal("Timeout waiting for PostgreSQL to become ready")
		}

		err := pool.Ping(ctx)
		if err == nil {
			colorPrint(fmt.Sprintf("Connected to PostgreSQL at %s:%d", cfg.Host, cfg.Port), "green")
			break
		}

		colorPrint(fmt.Sprintf("Waiting for Host '%s' on port '%d'...", cfg.Host, cfg.Port), "yellow")
		time.Sleep(1 * time.Second)
	}
}

func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists bool
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)
	
	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return fmt.Errorf("failed to check user existence: %w", err)
	}

	if !exists {
		colorPrint(fmt.Sprintf("Create User %s...", cfg.User), "green")
		
		sql := fmt.Sprintf("CREATE ROLE \"%s\" LOGIN PASSWORD '%s'", cfg.User, cfg.UserPass)
		
		if cfg.UserFlags != "" {
			flags := strings.Fields(cfg.UserFlags)
			for _, flag := range flags {
				switch flag {
				case "--createdb": sql += " CREATEDB"
				case "--createrole": sql += " CREATEROLE"
				case "--inherit": sql += " INHERIT"
				case "--no-login": sql += " NOLOGIN"
				case "--replication": sql += " REPLICATION"
				case "--superuser": sql += " SUPERUSER"
				case "--no-superuser": sql += " NOSUPERUSER"
				default:
					if strings.HasPrefix(flag, "--") {
						log.Printf("Warning: Unsupported user flag: %s", flag)
					}
				}
			}
		}
		
		if _, err = pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}
	return nil
}

func updateUserPassword(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	colorPrint(fmt.Sprintf("Update password for user %s...", cfg.User), "green")
	_, err := pool.Exec(ctx, "ALTER USER $1 WITH ENCRYPTED PASSWORD $2", cfg.User, cfg.UserPass)
	return err
}

func processDatabases(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	for _, dbname := range strings.Fields(cfg.DBName) {
		var exists bool
		err := pool.QueryRow(ctx, "SELECT 1 FROM pg_database WHERE datname = $1", dbname).Scan(&exists)
		
		if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
			return fmt.Errorf("failed to check database existence: %w", err)
		}

		if !exists {
			colorPrint(fmt.Sprintf("Create Database %s...", dbname), "green")
			if _, err = pool.Exec(ctx, "CREATE DATABASE $1 OWNER $2", dbname, cfg.User); err != nil {
				return fmt.Errorf("failed to create database: %w", err)
			}

			initFile := fmt.Sprintf("%s/%s.sql", cfg.InitSQLDir, dbname)
			if _, err := os.Stat(initFile); err == nil {
				colorPrint("Initialize Database...", "green")
				if err := executeInitScript(ctx, cfg, dbname, initFile); err != nil {
					return err
				}
			}
		}

		colorPrint("Update User Privileges on Database...", "green")
		if _, err = pool.Exec(ctx, "GRANT ALL PRIVILEGES ON DATABASE $1 TO $2", dbname, cfg.User); err != nil {
			return fmt.Errorf("failed to grant privileges: %w", err)
		}
	}
	return nil
}

func executeInitScript(ctx context.Context, cfg Config, dbname, initFile string) error {
	sqlContent, err := os.ReadFile(initFile)
	if err != nil {
		return fmt.Errorf("failed to read SQL file: %w", err)
	}
	
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		return fmt.Errorf("failed to parse db config: %w", err)
	}

	config.ConnConfig.Host = cfg.Host
	config.ConnConfig.Port = uint16(cfg.Port)
	config.ConnConfig.User = cfg.SuperUser
	config.ConnConfig.Password = cfg.SuperPass
	config.ConnConfig.Database = dbname

	dbPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer dbPool.Close()
	
	if _, err = dbPool.Exec(ctx, string(sqlContent)); err != nil {
		return fmt.Errorf("failed to execute init script: %w", err)
	}
	return nil
}

func colorPrint(text, color string) {
	var colorCode string
	switch color {
	case "red": colorCode = "\033[31m"
	case "green": colorCode = "\033[32m"
	case "yellow": colorCode = "\033[33m"
	default: colorCode = "\033[0m"
	}
	fmt.Printf("%s%s\033[0m\n", colorCode, text)
}
