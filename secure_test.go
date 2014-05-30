package secure

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

var myHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

func Test_No_Config(t *testing.T) {
	s := New(Options{
	// Intentionally left blank.
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), "bar")
}

func Test_No_AllowHosts(t *testing.T) {
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

func Test_Good_Single_AllowHosts(t *testing.T) {
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

func Test_Bad_Single_AllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"sub.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func Test_Good_Multiple_AllowHosts(t *testing.T) {
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

func Test_Bad_Multiple_AllowHosts(t *testing.T) {
	s := New(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func Test_AllowHosts_Dev_Mode(t *testing.T) {
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

func Test_SSL(t *testing.T) {
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

func Test_SSL_In_Dev_Mode(t *testing.T) {
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

func Test_Basic_SSL(t *testing.T) {
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

func Test_Basic_SSL_With_Host(t *testing.T) {
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

func Test_Bad_Proxy_SSL(t *testing.T) {
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

func Test_Custom_Proxy_SSL(t *testing.T) {
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

func Test_Custom_Proxy_SSL_In_Dev_Mode(t *testing.T) {
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

func Test_Custom_Proxy_And_Host_SSL(t *testing.T) {
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

func Test_Custom_Bad_Proxy_And_Host_SSL(t *testing.T) {
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

func Test_STS_Header(t *testing.T) {
	s := New(Options{
		STSSeconds: 315360000,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000")
}

func Test_STS_Header_In_Dev_Mode(t *testing.T) {
	s := New(Options{
		STSSeconds:    315360000,
		IsDevelopment: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func Test_STS_Header_With_Subdomain(t *testing.T) {
	s := New(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubdomains")
}

func Test_Frame_Deny(t *testing.T) {
	s := New(Options{
		FrameDeny: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
}

func Test_Custom_Frame_Value(t *testing.T) {
	s := New(Options{
		CustomFrameOptionsValue: "SAMEORIGIN",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func Test_Custom_Frame_Value_With_Deny(t *testing.T) {
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

func Test_Content_Nosniff(t *testing.T) {
	s := New(Options{
		ContentTypeNosniff: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Content-Type-Options"), "nosniff")
}

func Test_XSS_Protection(t *testing.T) {
	s := New(Options{
		BrowserXssFilter: true,
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "1; mode=block")
}

func Test_CSP(t *testing.T) {
	s := New(Options{
		ContentSecurityPolicy: "default-src 'self'",
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
