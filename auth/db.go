package auth

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	_ "github.com/golang-migrate/migrate/source/file"

	_ "github.com/lib/pq"
)

type UserStore interface {
	GetUserByUsername(string) (user, error)
	GetUserByUID(int64) (user, error)
	CheckTokenRevocation(jti string) (bool, error)
}

type psqlUserStore struct {
	db *sql.DB
}

func NewPsqlUserStore(db *sql.DB) psqlUserStore {
	s := psqlUserStore{db: db}

	// migration code
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal("err", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://app/migrations",
		"postgres", driver)
	if err != nil {
		log.Fatal("err", err)
	}
	m.Up()
	// end migration code

	return s
}

func (s psqlUserStore) GetUserByUsername(un string) (user, error) {
	var u user
	row := s.db.QueryRow("SELECT * FROM users WHERE username=$1;", un)
	err := row.Scan(&u.UID, &u.Username, &u.Password)
	if err != nil {
		return u, err
	}
	return u, nil
}

func (s psqlUserStore) GetUserByUID(uid int64) (user, error) {
	var u user
	row := s.db.QueryRow("SELECT * FROM users WHERE uid=$1;", uid)
	err := row.Scan(&u.UID, &u.Username, &u.Password)
	if err != nil {
		return u, err
	}
	return u, nil
}

func (s psqlUserStore) CheckTokenRevocation(jti string) (bool, error) {
	err := s.db.QueryRow("SELECT * FROM revoked_tokens WHERE jti=$1;", jti).Scan()
	if err == sql.ErrNoRows {
		return false, nil
	} else {
		return true, fmt.Errorf("Error checking revoked tokens. Err: %v", err)
	}
	return false, nil
}
