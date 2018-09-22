package auth

func (s *server) getUserByUsername(un string) (user, error) {
	var u user
	row := s.db.QueryRow("SELECT * FROM users WHERE username=$1;", un)
	err := row.Scan(&u.ID, &u.Username, &u.Password)
	if err != nil {
		return u, err
	}
	return u, nil
}
