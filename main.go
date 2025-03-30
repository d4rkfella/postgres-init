package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"strconv"
	"net/url"
	"time"
	"log"

	"github.com/jackc/pgx/v5"
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
	if err == nil {
		return ""
	}
	msg := err.Error()
	if idx := strings.Index(msg, "SQLSTATE "); idx != -1 {
		if idx+14 <= len(msg) {
			return msg[idx+9 : idx+14]
		}
	}
	return ""
}

func isAuthError(err error) bool {
    return strings.Contains(err.Error(), "password authentication failed") ||
        strings.Contains(err.Error(), "role \"") ||
        strings.Contains(err.Error(), "authentication failed") ||
        strings.Contains(err.Error(), "SASL authentication failed")
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

	// Load required variables
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

	// Load and validate port
	portStr := getEnvWithDefault("INIT_POSTGRES_PORT", "5432")
	cfg.Port, err = strconv.Atoi(portStr)
	if err != nil {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_PORT",
			Detail:    "invalid port number",
			Expected:  "integer between 1-65535",
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return Config{}, &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_PORT",
			Detail:    "port out of range",
			Expected:  "1-65535",
		}
	}

	// Load optional values
	cfg.UserFlags = os.Getenv("INIT_POSTGRES_USER_FLAGS")
	cfg.SSLMode = getEnvWithDefault("INIT_POSTGRES_SSLMODE", "disable")
	cfg.SSLRootCert = os.Getenv("INIT_POSTGRES_SSLROOTCERT")

	// Validate SSL config
	if err := validateSSLConfig(cfg.SSLMode, cfg.SSLRootCert); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validateSSLConfig(sslMode, sslRootCert string) error {
	allowedModes := map[string]bool{
		"disable":     true,
		"allow":       true,
		"prefer":      true,
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
	}

	if !allowedModes[sslMode] {
		return &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_SSLMODE",
			Detail:    "invalid SSL mode",
			Expected:  "one of: disable, allow, prefer, require, verify-ca, verify-full",
		}
	}

	if (sslMode == "verify-ca" || sslMode == "verify-full") && sslRootCert == "" {
		return &ConfigError{
			Operation: "validation",
			Variable:  "INIT_POSTGRES_SSLROOTCERT",
			Detail:    "SSL certificate required",
			Expected:  "path to SSL root certificate",
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

    connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
        url.QueryEscape(cfg.SuperUser),
        url.QueryEscape(cfg.SuperPass),
        cfg.Host,
        cfg.Port,
        url.QueryEscape(cfg.SuperUser),
        cfg.SSLMode)

    pool, err := pgxpool.New(ctx, connStr)
    if err != nil {
        return nil, &DatabaseError{
            Operation: "configuration",
            Detail:   "invalid connection parameters",
            Target:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
            Advice:   "Check host, port, and SSL configuration",
            Err:      err,
        }
    }
    defer func() {
        if err != nil {
            pool.Close()
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
            case <-time.After(baseDelay):
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
func createUser(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	var exists int
	err := pool.QueryRow(ctx, "SELECT 1 FROM pg_roles WHERE rolname = $1", cfg.User).Scan(&exists)

	if err != nil && !strings.Contains(err.Error(), "no rows in result set") {
		return &DatabaseError{
			Operation: "user check",
			Detail:   fmt.Sprintf("failed to verify user %q", cfg.User),
			Target:   cfg.User,
			Advice:   "Check database permissions and connection",
			Err:      err,
		}
	}

	if exists != 1 {
		colorPrint(fmt.Sprintf("👤 Creating user %s...", cfg.User), "green")
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
				Target:   cfg.User,
				Advice:   "Verify user creation privileges",
				Err:      err,
			}
		}
	} else {
		colorPrint(fmt.Sprintf("👤 Updating password for existing user %s...", cfg.User), "green")
		sql := fmt.Sprintf(
			`ALTER ROLE %s WITH ENCRYPTED PASSWORD %s`,
			pgx.Identifier{cfg.User}.Sanitize(),
			quoteLiteral(cfg.UserPass),
		)

		if _, err = pool.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "user update",
				Detail:   fmt.Sprintf("failed to update password for %s", pgx.Identifier{cfg.User}.Sanitize()),
				Target:   cfg.User,
				Advice:   "Check password requirements and user permissions",
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
			Detail:   fmt.Sprintf("failed to verify database %q", cfg.DBName),
			Target:   cfg.DBName,
			Advice:   "Check database connection and permissions",
			Err:      err,
		}
	}

	if exists != 1 {
		colorPrint(fmt.Sprintf("📦 Creating database %s...", cfg.DBName), "green")
		sql := fmt.Sprintf(
			`CREATE DATABASE %s OWNER %s`,
			pgx.Identifier{cfg.DBName}.Sanitize(),
			pgx.Identifier{cfg.User}.Sanitize(),
		)
		if _, err = pool.Exec(ctx, sql); err != nil {
			return &DatabaseError{
				Operation: "database creation",
				Detail:   fmt.Sprintf("failed to create database %s", pgx.Identifier{cfg.DBName}.Sanitize()),
				Target:   cfg.DBName,
				Advice:   "Verify user has CREATEDB privilege",
				Err:      err,
			}
		}
	}

	colorPrint(fmt.Sprintf("🔑 Granting privileges to user %q on database %q...", cfg.User, cfg.DBName), "green")
	sql := fmt.Sprintf(
		`GRANT ALL PRIVILEGES ON DATABASE %s TO %s`,
		pgx.Identifier{cfg.DBName}.Sanitize(),
		pgx.Identifier{cfg.User}.Sanitize(),
	)
	if _, err = pool.Exec(ctx, sql); err != nil {
		return &DatabaseError{
			Operation: "privileges assignment",
			Detail:   fmt.Sprintf("failed to grant privileges on %s", pgx.Identifier{cfg.DBName}.Sanitize()),
			Target:   cfg.DBName,
			Advice:   "Check user permissions and database ownership",
			Err:      err,
		}
	}
	
	return nil
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

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    pool, err := connectAndWait(ctx, cfg)
    if err != nil {
        return err
    }
    defer pool.Close()

    if err := createUser(ctx, pool, cfg); err != nil {
        return err
    }

    if err := createDatabase(ctx, pool, cfg); err != nil {
        return err
    }

    return nil
}
