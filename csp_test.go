package secure

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

//nolint:gochecknoglobals
var cspHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(CSPNonce(r.Context())))
})

func TestCSPNonce(t *testing.T) {
	csp := "default-src 'self' $NONCE; script-src 'strict-dynamic' $NONCE"
	cases := []struct {
		options Options
		headers []string
	}{
		{Options{ContentSecurityPolicy: csp}, []string{"Content-Security-Policy"}},
		{Options{ContentSecurityPolicyReportOnly: csp}, []string{"Content-Security-Policy-Report-Only"}},
		{
			Options{ContentSecurityPolicy: csp, ContentSecurityPolicyReportOnly: csp},
			[]string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"},
		},
	}

	for _, c := range cases {
		s := New(c.options)

		res := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/foo", nil)

		s.Handler(cspHandler).ServeHTTP(res, req)

		expect(t, res.Code, http.StatusOK)

		for _, header := range c.headers {
			csp := res.Header().Get(header)
			expect(t, strings.Count(csp, "'nonce-"), 2)

			nonce := strings.Split(strings.Split(csp, "'")[3], "-")[1]
			// Test that the context has the CSP nonce, but only during the request.
			expect(t, res.Body.String(), nonce)
			expect(t, CSPNonce(req.Context()), "")

			_, err := base64.RawStdEncoding.DecodeString(nonce)
			expect(t, err, nil)

			expect(t, csp, fmt.Sprintf("default-src 'self' 'nonce-%[1]s'; script-src 'strict-dynamic' 'nonce-%[1]s'", nonce))
		}
	}
}

func TestWithCSPNonce(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/foo", nil)

	nonce := "jdgKGHkbnd+/"

	expect(t, CSPNonce(withCSPNonce(req, nonce).Context()), nonce)
}

func TestCSPNoncePreservesStaticPolicy(t *testing.T) {
	policies := []string{
		"default-src 'self'",
		"default-src 'self'; report-uri https://example.com/a%20b%2Fc%25",
	}

	for _, policy := range policies {
		for _, nonceHeader := range []string{cspHeader, cspReportOnlyHeader} {
			t.Run(nonceHeader+"/"+policy, func(t *testing.T) {
				options := Options{ContentSecurityPolicy: policy, ContentSecurityPolicyReportOnly: policy}
				staticHeader := cspReportOnlyHeader
				if nonceHeader == cspHeader {
					options.ContentSecurityPolicy = "script-src $NONCE"
				} else {
					options.ContentSecurityPolicyReportOnly = "script-src $NONCE"
					staticHeader = cspHeader
				}

				res := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/foo", nil)
				New(options).Handler(cspHandler).ServeHTTP(res, req)

				nonce := res.Body.String()
				if nonce == "" {
					t.Fatal("handler received no nonce")
				}
				expect(t, res.Header().Get(nonceHeader), "script-src 'nonce-"+nonce+"'")
				expect(t, res.Header().Get(staticHeader), policy)
			})
		}
	}
}

func TestCSPNoncePreservesPercentEncodedURLs(t *testing.T) {
	const policy = "script-src $NONCE; style-src $NONCE; report-uri https://example.com/a%20b%2Fc%25"
	cases := []struct {
		name    string
		options Options
		headers []string
	}{
		{"enforced", Options{ContentSecurityPolicy: policy}, []string{cspHeader}},
		{"report only", Options{ContentSecurityPolicyReportOnly: policy}, []string{cspReportOnlyHeader}},
		{
			"both",
			Options{ContentSecurityPolicy: policy, ContentSecurityPolicyReportOnly: policy},
			[]string{cspHeader, cspReportOnlyHeader},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := New(c.options).Handler(cspHandler)
			var previousNonce string
			for request := 0; request < 2; request++ {
				res := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/foo", nil)
				handler.ServeHTTP(res, req)

				nonce := res.Body.String()
				if nonce == "" || nonce == previousNonce {
					t.Fatal("handler did not receive a fresh nonce")
				}
				previousNonce = nonce

				want := "script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce +
					"'; report-uri https://example.com/a%20b%2Fc%25"
				for _, header := range c.headers {
					expect(t, res.Header().Get(header), want)
				}
				expect(t, CSPNonce(req.Context()), "")
			}
		})
	}
}
