package auth

// routes
func (s *server) routes() {
	s.router.Handle("/", s.rootHandler())
	s.router.Handle("/login", s.loginHandler())
	s.router.Handle("/test", s.AuthnMw(s.rootHandler()))
}
