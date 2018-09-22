package auth

import (
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func (s *server) logEntry(r *http.Request) *logrus.Entry {
	// we discard error here, because if os.Hostname() fails, all hope is lost.
	host, _ := os.Hostname()
	entry := s.log.WithFields(logrus.Fields{
		"host":       host,
		"ip":         strings.Split(r.RemoteAddr, ":")[0],
		"method":     r.Method,
		"uri":        r.RequestURI,
		"request_id": r.Context().Value("request_id"),
	})
	return entry
}
