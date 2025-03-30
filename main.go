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

type ConfigError struct {
	Operation string
	Detail    string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s: %s", e.Operation, e.Detail)
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
		return err
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

type Config struct {
	Host        string `redact:"false"`
	Port        int    `redact:"false"`
	SuperUser   string `redact:"false"`
	SuperPass   string `redact:"true"`
	User        string `redact:"false"`
	UserPass    string `redact:"true"`
	DBName      string `redact:"false"`
	UserFlags   string `redact:"false"`
	SSLMode     string `redact:"false"`
	SSLRootCert string `redact:"false"`
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

func redactString(s string) string {
	if s == "" {
		return `""`
	}
	return `"[REDACTED]"`
}

func loadConfig() (Config, error) {
    var cfg Config

    cfg.SuperUser = os.Getenv("INIT_POSTGRES_SUPER_USER")
    cfg.SuperPass = os.Getenv("INIT_POSTGRES_SUPER_PASS")
    cfg.User = os.Getenv("INIT_POSTGRES_USER")
    cfg.UserPass = os.Getenv("INIT_POSTGRES_PASS")
    cfg.DBName = os.Getenv("INIT_POSTGRES_DBNAME")
    cfg.Host = os.Getenv("INIT_POSTGRES_HOST")

    cfg.UserFlags = os.Getenv("INIT_POSTGRES_USER_FLAGS")
    cfg.SSLMode = getEnvWithDefault("INIT_POSTGRES_SSLMODE", "disable")
    cfg.SSLRootCert = os.Getenv("INIT_POSTGRES_SSLROOTCERT")

    portStr := getEnvWithDefault("INIT_POSTGRES_PORT", "5432")

    if err := validateConfig(&cfg, portStr); err != nil {
        return Config{}, err
    }

    return cfg, nil
}

func validateConfig(cfg *Config, portStr string) error {
    var err error

    required := []struct{
        key   string
        field *string
    }{
        {"INIT_POSTGRES_SUPER_USER", &cfg.SuperUser},
        {"INIT_POSTGRES_SUPER_PASS", &cfg.SuperPass},
        {"INIT_POSTGRES_USER", &cfg.User},
        {"INIT_POSTGRES_PASS", &cfg.UserPass},
        {"INIT_POSTGRES_DBNAME", &cfg.DBName},
        {"INIT_POSTGRES_HOST", &cfg.Host},
    }

    for _, req := range required {
        if *req.field, err = getRequiredEnv(req.key); err != nil {
            return configError("", req.key, err)
        }
    }

    cfg.Port, err = strconv.Atoi(portStr)
    if err != nil {
        return configError("invalid port number", portStr, err)
    }

    if cfg.Port < 1 || cfg.Port > 65535 {
        return configError("invalid port range", strconv.Itoa(cfg.Port), nil)
    }

    allowedModes := map[string]bool{
        "disable":     true,
        "allow":       true,
        "prefer":      true,
        "require":     true,
        "verify-ca":   true,
        "verify-full": true,
    }

    if !allowedModes[cfg.SSLMode] {
        return configError("invalid SSL mode", cfg.SSLMode, nil)
    }

    if (cfg.SSLMode == "verify-ca" || cfg.SSLMode == "verify-full") && cfg.SSLRootCert == "" {
        return configError("SSL mode requires SSLRootCert to be set", fmt.Sprintf("%q", cfg.SSLMode), nil)
    }

    return nil
}

func configError(context, value string, err error) error {
	msg := fmt.Sprintf("%s: %q", context, value)
	if err != nil {
		msg += fmt.Sprintf(" (%v)", err)
	}
	return &ConfigError{
		Operation: "configuration",
		Detail:   msg,
	}
}

func getRequiredEnv(key string) (string, error) {
    if value := os.Getenv(key); value != "" {
        return value, nil
    }
    return "", fmt.Errorf("required environment variable %s not set", key)
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func connectPostgres(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(cfg.SuperUser), 
		url.QueryEscape(cfg.SuperPass),
		cfg.Host, 
		cfg.Port, 
		url.QueryEscape(cfg.SuperUser), 
		cfg.SSLMode)

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
			Detail:   fmt.Sprintf("failed to verify the existence of user '%s'", cfg.User),
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
				Detail:   fmt.Sprintf("failed to update the password for user %s", pgx.Identifier{cfg.User}.Sanitize()),
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
			Detail:   fmt.Sprintf("failed to verify the existence of database '%s'", cfg.DBName),
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
