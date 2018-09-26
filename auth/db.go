package auth

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type UserStore interface {
	GetUserByUsername(string) (user, error)
}

type psqlUserStore struct {
	db *sql.DB
}

func NewPsqlUserStore(db *sql.DB) psqlUserStore {
	s := psqlUserStore{db: db}
	return s
}

func (s psqlUserStore) GetUserByUsername(un string) (user, error) {
	var u user
	row := s.db.QueryRow("SELECT * FROM users WHERE username=$1;", un)
	err := row.Scan(&u.ID, &u.Username, &u.Password)
	if err != nil {
		return u, err
	}
	return u, nil
}
