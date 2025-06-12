package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v3"
	pgx "github.com/jackc/pgx/v5"
)

func TestCreateUser(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		User:      "testuser",
		UserPass:  "testpassword",
		UserFlags: "CREATEDB",
	}

	t.Run("Create new user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable})
		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.User).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec("CREATE ROLE").WillReturnResult(pgxmock.NewResult("CREATE ROLE", 1))
		mock.ExpectCommit()
		mock.ExpectRollback()

		if err := createUser(ctx, mock, cfg); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("Update existing user", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable})
		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.User).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectExec("ALTER ROLE").WillReturnResult(pgxmock.NewResult("ALTER ROLE", 1))
		mock.ExpectCommit()
		mock.ExpectRollback()

		if err := createUser(ctx, mock, cfg); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("Invalid user flags", func(t *testing.T) {
		invalidCfg := Config{
			User:      "testuser",
			UserPass:  "testpassword",
			UserFlags: "INVALID_FLAG",
		}

		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		err = createUser(ctx, mock, invalidCfg)
		if err == nil {
			t.Error("expected error but got none")
			return
		}

		if !strings.Contains(err.Error(), "invalid user flag") {
			t.Errorf("expected invalid flag error but got: %v", err)
		}
	})

	t.Run("Transaction begin failure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		expectedErr := fmt.Errorf("transaction begin error")
		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable}).WillReturnError(expectedErr)

		err = createUser(ctx, mock, cfg)
		if err == nil {
			t.Error("expected error but got none")
			return
		}

		if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Errorf("expected error containing %q but got %q", expectedErr.Error(), err.Error())
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
}

func TestCreateDatabase(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		User:   "testuser",
		DBName: "testdb",
	}

	t.Run("Create new database", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.DBName).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec("CREATE DATABASE").WillReturnResult(pgxmock.NewResult("CREATE DATABASE", 1))
		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable})
		mock.ExpectExec("GRANT ALL PRIVILEGES").WillReturnResult(pgxmock.NewResult("GRANT", 1))
		mock.ExpectCommit()
		mock.ExpectRollback()

		err = createDatabase(ctx, mock, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("Grant privileges on existing database", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.DBName).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable})
		mock.ExpectExec("GRANT ALL PRIVILEGES").WillReturnResult(pgxmock.NewResult("GRANT", 1))
		mock.ExpectCommit()
		mock.ExpectRollback()

		err = createDatabase(ctx, mock, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("Database creation failure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.DBName).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec("CREATE DATABASE").WillReturnError(&pgconn.PgError{
			Severity:         "ERROR",
			Code:            "42P04",
			Message:         "database already exists",
			Position:        0,
			InternalQuery:   "",
			InternalPosition: 0,
			Where:           "",
			SchemaName:      "",
			TableName:       "",
			ColumnName:      "",
			DataTypeName:    "",
			ConstraintName:  "",
			File:           "",
			Line:           0,
			Routine:        "",
		})

		err = createDatabase(ctx, mock, cfg)
		if err == nil {
			t.Error("expected error but got none")
			return
		}

		var dbErr *DatabaseError
		if !errors.As(err, &dbErr) {
			t.Errorf("expected DatabaseError but got %T", err)
			return
		}

		if dbErr.Code != "42P04" {
			t.Errorf("expected error code 42P04 but got %s", dbErr.Code)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})

	t.Run("Grant privileges failure", func(t *testing.T) {
		mock, err := pgxmock.NewPool()
		if err != nil {
			t.Fatal(err)
		}
		defer mock.Close()

		mock.ExpectQuery("SELECT EXISTS").WithArgs(cfg.DBName).WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.Serializable})
		mock.ExpectExec("GRANT ALL PRIVILEGES").WillReturnError(&pgconn.PgError{
			Severity:         "ERROR",
			Code:            "42501",
			Message:         "permission denied to grant privileges",
			Position:        0,
			InternalQuery:   "",
			InternalPosition: 0,
			Where:           "",
			SchemaName:      "",
			TableName:       "",
			ColumnName:      "",
			DataTypeName:    "",
			ConstraintName:  "",
			File:           "",
			Line:           0,
			Routine:        "",
		})
		mock.ExpectRollback()

		err = createDatabase(ctx, mock, cfg)
		if err == nil {
			t.Error("expected error but got none")
			return
		}

		var dbErr *DatabaseError
		if !errors.As(err, &dbErr) {
			t.Errorf("expected DatabaseError but got %T", err)
			return
		}

		if dbErr.Code != "42501" {
			t.Errorf("expected error code 42501 but got %s", dbErr.Code)
		}

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("unfulfilled expectations: %s", err)
		}
	})
} 