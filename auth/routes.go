package auth

// routes
func (s *server) routes() {
	s.router.Use(s.requestIDMw)

	s.router.Handle("/", s.rootHandler()).Methods("GET")
	s.router.Handle("/login", s.loginHandler()).Methods("POST")
	s.router.Handle("/test", s.AuthnMw(s.rootHandler())).Methods("GET")
	s.router.Handle("/refresh", s.refreshHandler()).Methods("GET")
}
