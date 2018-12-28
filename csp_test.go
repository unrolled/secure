package secure

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cspHandler writes the nonce out as the response body.
var cspHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(CSPNonce(r.Context())))
})

func TestCSPNonce(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicy: "default-src 'self' $NONCE; script-src 'strict-dynamic' $NONCE",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(cspHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)

	csp := res.Header().Get("Content-Security-Policy")
	expect(t, strings.Count(csp, "'nonce-"), 2)

	nonce := strings.Split(strings.Split(csp, "'")[3], "-")[1]
	// Test that the context has the CSP nonce, but only during the request.
	expect(t, res.Body.String(), nonce)
	expect(t, CSPNonce(req.Context()), "")

	_, err := base64.RawStdEncoding.DecodeString(nonce)
	expect(t, err, nil)

	expect(t, csp, fmt.Sprintf("default-src 'self' 'nonce-%[1]s'; script-src 'strict-dynamic' 'nonce-%[1]s'", nonce))
}

func TestWithCSPNonce(t *testing.T) {
	req, _ := http.NewRequest("GET", "/foo", nil)

	nonce := "jdgKGHkbnd+/"

	expect(t, CSPNonce(withCSPNonce(req, nonce).Context()), nonce)
}
