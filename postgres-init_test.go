package main

import (
	"context"
	"testing"

	"github.com/pashagolub/pgxmock"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateUser(t *testing.T) {
	// Create a mock database connection using pgxmock.NewConn
	mockConn, mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("Failed to create mock database connection: %v", err)
	}
	defer mockConn.Close()

	// Set up a mock pool with the mock connection
	mockPool := pgxpool.Pool(mockConn)

	// Set expectations for the mock database query
	mock.ExpectQuery(`SELECT 1 FROM pg_roles WHERE rolname = \$1`).
		WithArgs("testuser").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(0))

	mock.ExpectExec(`CREATE ROLE "testuser" LOGIN ENCRYPTED PASSWORD 'testpassword'`).
		WillReturnResult(pgxmock.NewResult("CREATE", 1))

	// Define the configuration you want to pass
	cfg := Config{
		User:     "testuser",
		UserPass: "testpassword",
	}

	// Call the function you want to test
	err = createUser(context.Background(), mockPool, cfg)
	if err != nil {
		t.Fatalf("Error in createUser: %v", err)
	}

	// Ensure mock expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Fatalf("There were unmet expectations: %v", err)
	}
}

func TestCreateDatabase(t *testing.T) {
	// Create a mock database connection using pgxmock.NewConn
	mockConn, mock, err := pgxmock.NewConn()
	if err != nil {
		t.Fatalf("Failed to create mock database connection: %v", err)
	}
	defer mockConn.Close()

	// Set up a mock pool with the mock connection
	mockPool := pgxpool.Pool(mockConn)

	// Set expectations for the mock database query
	mock.ExpectQuery(`SELECT 1 FROM pg_database WHERE datname = \$1`).
		WithArgs("testdb").
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(0))

	mock.ExpectExec(`CREATE DATABASE "testdb" OWNER "testuser"`).
		WillReturnResult(pgxmock.NewResult("CREATE", 1))

	// Define the configuration you want to pass
	cfg := Config{
		DBName: "testdb",
		User:   "testuser",
	}

	// Call the function you want to test
	err = createDatabase(context.Background(), mockPool, cfg)
	if err != nil {
		t.Fatalf("Error in createDatabase: %v", err)
	}

	// Ensure mock expectations were met
	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Fatalf("There were unmet expectations: %v", err)
	}
}
