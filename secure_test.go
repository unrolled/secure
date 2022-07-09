package secure

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

func TestNoConfig(t *testing.T) {
	s := New()

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), "bar")
}

func TestNoAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestGoodSingleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"www.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestBadSingleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"sub.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func TestRegexSingleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts:         []string{"*\\.example\\.com"},
		AllowedHostsAreRegex: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "sub.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestRegexMultipleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts:         []string{".+\\.example\\.com", ".*sub\\..+-awesome-example\\.com"},
		AllowedHostsAreRegex: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "sub.first-awesome-example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)

	res = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/foo", nil)
	req.Host = "test.sub.second-awesome-example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)

	res = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/foo", nil)
	req.Host = "test.sub.second-example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func TestInvalidRegexAllowHosts(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	New(Options{
		AllowedHosts:         []string{"[*.e"},
		AllowedHostsAreRegex: true,
	})
}

func TestGoodSingleAllowHostsProxyHeaders(t *testing.T) {
	s := New(Options{
		AllowedHosts:      []string{"www.example.com"},
		HostsProxyHeaders: []string{"X-Proxy-Host"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "example-internal"
	req.Header.Set("X-Proxy-Host", "www.example.com")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestBadSingleAllowHostsProxyHeaders(t *testing.T) {
	s := New(Options{
		AllowedHosts:      []string{"sub.example.com"},
		HostsProxyHeaders: []string{"X-Proxy-Host"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "example-internal"
	req.Header.Set("X-Proxy-Host", "www.example.com")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func TestGoodMultipleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "sub.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestBadMultipleAllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func TestAllowHostsInDevMode(t *testing.T) {
	s := New(Options{
		AllowedHosts:  []string{"www.example.com", "sub.example.com"},
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestBadHostHandler(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	badHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "BadHost", http.StatusInternalServerError)
	})

	s.SetBadHostHandler(badHandler)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)

	// http.Error outputs a new line character with the response.
	expect(t, res.Body.String(), "BadHost\n")
}

func TestSSL(t *testing.T) {
	s := New(Options{
		SSLRedirect: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestSSLInDevMode(t *testing.T) {
	s := New(Options{
		SSLRedirect:   true,
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestBasicSSL(t *testing.T) {
	s := New(Options{
		SSLRedirect: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

func TestBasicSSLWithHost(t *testing.T) {
	s := New(Options{
		SSLRedirect: true,
		SSLHost:     "secure.example.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
}

func TestBasicSSLWithHostFunc(t *testing.T) {
	sslHostFunc := (func() SSLHostFunc {
		isServerDown := false
		return func(host string) (newHost string) {
			if isServerDown {
				newHost = "404.example.com"
				return
			}
			if host == "www.example.com" {
				newHost = "secure.example.com:8443"
			} else if host == "www.example.org" {
				newHost = "secure.example.org"
			}
			return
		}
	})()
	s := New(Options{
		SSLRedirect: true,
		SSLHostFunc: &sslHostFunc,
	})

	// test www.example.com
	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.com:8443/foo")

	// test www.example.org
	res = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.org"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.org/foo")

	// test other
	res = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/foo", nil)
	req.Host = "www.other.com"
	req.URL.Scheme = "http"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.other.com/foo")
}

func TestBadProxySSL(t *testing.T) {
	s := New(Options{
		SSLRedirect: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

func TestCustomProxySSL(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestCustomProxySSLInDevMode(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		IsDevelopment:   true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "http")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestCustomProxyAndHostProxyHeadersWithRedirect(t *testing.T) {
	s := New(Options{
		HostsProxyHeaders: []string{"X-Forwarded-Host"},
		SSLRedirect:       true,
		SSLProxyHeaders:   map[string]string{"X-Forwarded-Proto": "http"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "example-internal"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")
	req.Header.Add("X-Forwarded-Host", "www.example.com")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

func TestCustomProxyAndHostSSL(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		SSLHost:         "secure.example.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func TestCustomBadProxyAndHostSSL(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "superman"},
		SSLHost:         "secure.example.com",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
}

func TestCustomBadProxyAndHostSSLWithTempRedirect(t *testing.T) {
	s := New(Options{
		SSLRedirect:          true,
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "superman"},
		SSLHost:              "secure.example.com",
		SSLTemporaryRedirect: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusTemporaryRedirect)
	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
}

func TestStsHeaderWithNoSSL(t *testing.T) {
	s := New(Options{
		STSSeconds: 315360000,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithNoSSLButWithForce(t *testing.T) {
	s := New(Options{
		STSSeconds:     315360000,
		ForceSTSHeader: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000")
}

func TestStsHeaderWithNoSSLButWithForceForRequestOnly(t *testing.T) {
	s := New(Options{
		STSSeconds:     315360000,
		ForceSTSHeader: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithNoSSLButWithForceAndIsDev(t *testing.T) {
	s := New(Options{
		STSSeconds:     315360000,
		ForceSTSHeader: true,
		IsDevelopment:  true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithSSL(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:      315360000,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000")
}

func TestStsHeaderWithSSLForRequestOnly(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:      315360000,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderInDevMode(t *testing.T) {
	s := New(Options{
		STSSeconds:    315360000,
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithSubdomains(t *testing.T) {
	s := New(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubDomains")
}

func TestStsHeaderWithSubdomainsForRequestOnly(t *testing.T) {
	s := New(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithPreload(t *testing.T) {
	s := New(Options{
		STSSeconds: 315360000,
		STSPreload: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; preload")
}

func TestStsHeaderWithPreloadForRequest(t *testing.T) {
	s := New(Options{
		STSSeconds: 315360000,
		STSPreload: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestStsHeaderWithSubdomainsWithPreload(t *testing.T) {
	s := New(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
		STSPreload:           true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubDomains; preload")
}

func TestStsHeaderWithSubdomainsWithPreloadForRequestOnly(t *testing.T) {
	s := New(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
		STSPreload:           true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func TestFrameDeny(t *testing.T) {
	s := New(Options{
		FrameDeny: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
}

func TestFrameDenyForRequestOnly(t *testing.T) {
	s := New(Options{
		FrameDeny: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "")
}

func TestCustomFrameValue(t *testing.T) {
	s := New(Options{
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func TestCustomFrameValueWithDeny(t *testing.T) {
	s := New(Options{
		FrameDeny:               true,
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func TestCustomFrameValueWithDenyForRequestOnly(t *testing.T) {
	s := New(Options{
		FrameDeny:               true,
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "")
}

func TestContentNosniff(t *testing.T) {
	s := New(Options{
		ContentTypeNosniff: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Content-Type-Options"), "nosniff")
}

func TestContentNosniffForRequestOnly(t *testing.T) {
	s := New(Options{
		ContentTypeNosniff: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Content-Type-Options"), "")
}

func TestXSSProtection(t *testing.T) {
	s := New(Options{
		BrowserXssFilter: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "1; mode=block")
}

func TestXSSProtectionForRequestOnly(t *testing.T) {
	s := New(Options{
		BrowserXssFilter: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "")
}

func TestCustomXSSProtection(t *testing.T) {
	xssVal := "1; report=https://example.com"
	s := New(Options{
		CustomBrowserXssValue: xssVal,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), xssVal)
}

func TestCustomXSSProtectionForRequestOnly(t *testing.T) {
	xssVal := "1; report=https://example.com"
	s := New(Options{
		CustomBrowserXssValue: xssVal,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "")
}

func TestBothXSSProtection(t *testing.T) {
	xssVal := "0"
	s := New(Options{
		BrowserXssFilter:      true,
		CustomBrowserXssValue: xssVal,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), xssVal)
}

func TestBothXSSProtectionForRequestOnly(t *testing.T) {
	xssVal := "0"
	s := New(Options{
		BrowserXssFilter:      true,
		CustomBrowserXssValue: xssVal,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "")
}

func TestCsp(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicy: "default-src 'self'",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

func TestCspForRequestOnly(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicy: "default-src 'self'",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy"), "")
}

func TestCspReportOnly(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicyReportOnly: "default-src 'self'",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy-Report-Only"), "default-src 'self'")
}

func TestCspReportOnlyForRequestOnly(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicyReportOnly: "default-src 'self'",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy-Report-Only"), "")
}

func TestInlineSecure(t *testing.T) {
	s := New(Options{
		FrameDeny: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandlerFuncWithNext(w, r, nil)
		w.Write([]byte("bar"))
	})

	handler.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
}

func TestInlineSecureForRequestOnly(t *testing.T) {
	s := New(Options{
		FrameDeny: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandlerFuncWithNextForRequestOnly(w, r, nil)
		w.Write([]byte("bar"))
	})

	handler.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "")
}

// https://developer.mozilla.org/en-US/docs/Web/Security/Public_Key_Pinning
const hpkp = `pin-sha256="cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="; pin-sha256="M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="; max-age=5184000; includeSubdomains; report-uri="https://www.example.net/hpkp-report"`

func TestHPKP(t *testing.T) {
	s := New(Options{
		PublicKey: hpkp,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), hpkp)
}

func TestHPKPForRequestOnly(t *testing.T) {
	s := New(Options{
		PublicKey: hpkp,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPNotSet(t *testing.T) {
	s := New()

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPNotSetForRequestOnly(t *testing.T) {
	s := New()

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPInDevMode(t *testing.T) {
	s := New(Options{
		PublicKey:     hpkp,
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPInDevModeForRequestOnly(t *testing.T) {
	s := New(Options{
		PublicKey:     hpkp,
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPNonSSL(t *testing.T) {
	s := New(Options{
		PublicKey: hpkp,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestHPKPNonSSLForRequestOnly(t *testing.T) {
	s := New(Options{
		PublicKey: hpkp,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Public-Key-Pins"), "")
}

func TestReferrer(t *testing.T) {
	s := New(Options{
		ReferrerPolicy: "same-origin",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Referrer-Policy"), "same-origin")
}

func TestReferrerForRequestOnly(t *testing.T) {
	s := New(Options{
		ReferrerPolicy: "same-origin",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.HandlerForRequestOnly(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Referrer-Policy"), "")
}

func TestFeaturePolicy(t *testing.T) {
	s := New(Options{
		FeaturePolicy: "vibrate 'none';",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Feature-Policy"), "vibrate 'none';")
}

func TestPermissionsPolicy(t *testing.T) {
	s := New(Options{
		PermissionsPolicy: "geolocation=(self)",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Permissions-Policy"), "geolocation=(self)")
}

func TestCrossOriginOpenerPolicy(t *testing.T) {
	s := New(Options{
		CrossOriginOpenerPolicy: "same-origin",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Cross-Origin-Opener-Policy"), "same-origin")
}

func TestExpectCT(t *testing.T) {
	s := New(Options{
		ExpectCTHeader: `enforce, max-age=30, report-uri="https://www.example.com/ct-report"`,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Expect-CT"), `enforce, max-age=30, report-uri="https://www.example.com/ct-report"`)
}

func TestIsSSL(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	expect(t, s.isSSL(req), false)

	req, _ = http.NewRequest("GET", "/foo", nil)
	req.TLS = &tls.ConnectionState{
		CipherSuite: 16,
	}
	expect(t, s.isSSL(req), true)

	req, _ = http.NewRequest("GET", "/foo", nil)
	req.URL.Scheme = "https"
	expect(t, s.isSSL(req), true)

	req, _ = http.NewRequest("GET", "/foo", nil)
	req.Header.Add("X-Forwarded-Proto", "https")
	expect(t, s.isSSL(req), true)
}

func TestSSLForceHostWithHTTPS(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		SSLHost:         "secure.example.com",
		SSLForceHost:    true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "https"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
}

func TestSSLForceHostWithHTTP(t *testing.T) {
	s := New(Options{
		SSLHost:      "secure.example.com",
		SSLForceHost: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "http")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
}

func TestSSLForceHostWithSSLRedirect(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		SSLHost:         "secure.example.com",
		SSLForceHost:    true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "https"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
}

func TestSSLForceHostTemporaryRedirect(t *testing.T) {
	s := New(Options{
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
		SSLHost:              "secure.example.com",
		SSLForceHost:         true,
		SSLTemporaryRedirect: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "https"
	req.Header.Add("X-Forwarded-Proto", "https")

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusTemporaryRedirect)
}

func TestModifyResponseHeadersNoSSL(t *testing.T) {
	s := New(Options{
		SSLRedirect: false,
	})

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://example.com"}}

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "http://example.com")
}

func TestModifyResponseHeadersWithSSLAndDifferentSSLHost(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLHost:         "secure.example.com",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://example.com"}}
	res.Request = req

	expect(t, res.Header.Get("Location"), "http://example.com")

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "http://example.com")
}

func TestModifyResponseHeadersWithSSLAndNoSSLHost(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://example.com"}}
	res.Request = req

	expect(t, res.Header.Get("Location"), "http://example.com")

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "http://example.com")
}

func TestModifyResponseHeadersWithSSLAndMatchingSSLHost(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLHost:         "secure.example.com",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://secure.example.com"}}
	res.Request = req

	expect(t, res.Header.Get("Location"), "http://secure.example.com")

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "https://secure.example.com")
}

func TestModifyResponseHeadersWithSSLAndPortInLocationResponse(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLHost:         "secure.example.com",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://secure.example.com:877"}}
	res.Request = req

	expect(t, res.Header.Get("Location"), "http://secure.example.com:877")

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "http://secure.example.com:877")
}

func TestModifyResponseHeadersWithSSLAndPathInLocationResponse(t *testing.T) {
	s := New(Options{
		SSLRedirect:     true,
		SSLHost:         "secure.example.com",
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	})

	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	res := &http.Response{}
	res.Header = http.Header{"Location": []string{"http://secure.example.com/admin/login"}}
	res.Request = req

	expect(t, res.Header.Get("Location"), "http://secure.example.com/admin/login")

	err := s.ModifyResponseHeaders(res)
	expect(t, err, nil)

	expect(t, res.Header.Get("Location"), "https://secure.example.com/admin/login")
}

func TestCustomSecureContextKey(t *testing.T) {
	s1 := New(Options{
		BrowserXssFilter:      true,
		CustomBrowserXssValue: "0",
		SecureContextKey:      "totallySecureContextKey",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	var actual *http.Request
	hf := func(w http.ResponseWriter, r *http.Request) {
		actual = r
	}

	s1.HandlerFuncWithNextForRequestOnly(res, req, hf)
	contextHeaders := actual.Context().Value(s1.ctxSecureHeaderKey).(http.Header)
	expect(t, contextHeaders.Get(xssProtectionHeader), s1.opt.CustomBrowserXssValue)
}

func TestMultipleCustomSecureContextKeys(t *testing.T) {
	s1 := New(Options{
		BrowserXssFilter:      true,
		CustomBrowserXssValue: "0",
		SecureContextKey:      "totallySecureContextKey",
	})

	s2 := New(Options{
		FeaturePolicy:    "test",
		SecureContextKey: "anotherSecureContextKey",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	var actual *http.Request
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actual = r
	})

	next := s1.HandlerForRequestOnly(hf)
	s2.HandlerFuncWithNextForRequestOnly(res, req, next.ServeHTTP)

	s1Headers := actual.Context().Value(s1.ctxSecureHeaderKey).(http.Header)
	s2Headers := actual.Context().Value(s2.ctxSecureHeaderKey).(http.Header)

	expect(t, s1Headers.Get(xssProtectionHeader), s1.opt.CustomBrowserXssValue)
	expect(t, s2Headers.Get(featurePolicyHeader), s2.opt.FeaturePolicy)
}

func TestAllowRequestFuncTrue(t *testing.T) {
	s := New(Options{
		AllowRequestFunc: func(r *http.Request) bool { return true },
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.allow-request.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func TestAllowRequestFuncFalse(t *testing.T) {
	s := New(Options{
		AllowRequestFunc: func(r *http.Request) bool { return false },
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.deny-request.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusBadRequest)
}

func TestBadRequestHandler(t *testing.T) {
	s := New(Options{
		AllowRequestFunc: func(r *http.Request) bool { return false },
	})
	badRequestFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "custom error", http.StatusConflict)
	})
	s.SetBadRequestHandler(badRequestFunc)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.deny-request.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusConflict)
	expect(t, strings.TrimSpace(res.Body.String()), `custom error`)
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
