CREATE TABLE users
  (id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  passwordhash TEXT NOT NULL);

INSERT INTO users (username, passwordhash)
VALUES
  ('jordan',
    /* password == "test" */
  '$2y$12$HbdwCNzjxeHijMGzzatkvOmCw9sO1d5iSwDgmGacng9JjZp7R.Dgm');


CREATE TABLE revoked_tokens
  (jti PRIMARY KEY);
