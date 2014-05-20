package secure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/codegangsta/negroni"
)

func Test_No_Config(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
	// nothing here to configure
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func Test_No_AllowHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts: []string{},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func Test_Good_Single_AllowHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts: []string{"www.example.com"},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func Test_Bad_Single_AllowHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts: []string{"sub.example.com"},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func Test_Good_Multiple_AllowHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "sub.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), `bar`)
}

func Test_Bad_Multiple_AllowHosts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts: []string{"www.example.com", "sub.example.com"},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusInternalServerError)
}

func Test_AllowHosts_Dev_Mode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		AllowedHosts:  []string{"www.example.com", "sub.example.com"},
		IsDevelopment: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www3.example.com"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "https"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_SSL_In_Dev_Mode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect:   true,
		IsDevelopment: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_Basic_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

func Test_Basic_SSL_With_Host(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect: true,
		SSLHost:     "secure.example.com",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
}

func Test_Bad_Proxy_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://www.example.com/foo")
}

func Test_Custom_Proxy_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_Custom_Proxy_SSL_In_Dev_Mode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		IsDevelopment:   true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "http")

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_Custom_Proxy_And_Host_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
		SSLHost:         "secure.example.com",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
}

func Test_Custom_Bad_Proxy_And_Host_SSL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		SSLRedirect:     true,
		SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "superman"},
		SSLHost:         "secure.example.com",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	req.Host = "www.example.com"
	req.URL.Scheme = "http"
	req.Header.Add("X-Forwarded-Proto", "https")

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusMovedPermanently)
	expect(t, res.Header().Get("Location"), "https://secure.example.com/foo")
}

func Test_STS_Header(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		STSSeconds: 315360000,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000")
}

func Test_STS_Header_In_Dev_Mode(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		STSSeconds:    315360000,
		IsDevelopment: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "")
}

func Test_STS_Header_With_Subdomain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		STSSeconds:           315360000,
		STSIncludeSubdomains: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Strict-Transport-Security"), "max-age=315360000; includeSubdomains")
}

func Test_Frame_Deny(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		FrameDeny: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "DENY")
}

func Test_Custom_Frame_Value(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		CustomFrameOptionsValue: "SAMEORIGIN",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func Test_Custom_Frame_Value_With_Deny(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		FrameDeny:               true,
		CustomFrameOptionsValue: "SAMEORIGIN",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Frame-Options"), "SAMEORIGIN")
}

func Test_Content_Nosniff(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		ContentTypeNosniff: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Content-Type-Options"), "nosniff")
}

func Test_XSS_Protection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		BrowserXssFilter: true,
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-XSS-Protection"), "1; mode=block")
}

func Test_CSP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/foo", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "bar")
	})

	n := negroni.New()
	n.Use(NewSecure(Options{
		ContentSecurityPolicy: "default-src 'self'",
	}))
	n.UseHandler(mux)

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	n.ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("Content-Security-Policy"), "default-src 'self'")
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
