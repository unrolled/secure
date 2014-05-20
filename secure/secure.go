// Package secure is a middleware for Negroni that helps enable some quick security wins.
//
// package main
//
// import (
//   "fmt"
//   "net/http"
//
//   "github.com/codegangsta/negroni"
//   "github.com/unrolled/negroni-secure/secure"
// )
//
// func main() {
//   mux := http.NewServeMux()
//   mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
//     fmt.Fprintf(w, "Welcome to the home page!")
//   })
//
//   n := negroni.Classic()
//   n.UseHandler(mux)
//   n.Use(secure.NewSecure(secure.Options{
//     AllowedHosts: []string{"www.example.com", "sub.example.com"},
//     SSLRedirect: true,
//   }))
//   n.Run(":3000")
// }
package secure

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	stsHeader           = "Strict-Transport-Security"
	stsSubdomainString  = "; includeSubdomains"
	frameOptionsHeader  = "X-Frame-Options"
	frameOptionsValue   = "DENY"
	contentTypeHeader   = "X-Content-Type-Options"
	contentTypeValue    = "nosniff"
	xssProtectionHeader = "X-XSS-Protection"
	xssProtectionValue  = "1; mode=block"
	cspHeader           = "Content-Security-Policy"
)

// Options is a struct for specifying configuration options for the secure.Secure middleware.
type Options struct {
	// AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
	AllowedHosts []string
	// If SSLRedirect is set to true, then only allow https requests. Default is false.
	SSLRedirect bool
	// SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
	SSLHost string
	// SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
	SSLProxyHeaders map[string]string
	// STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
	STSSeconds int64
	// If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
	STSIncludeSubdomains bool
	// If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
	FrameDeny bool
	// CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option.
	CustomFrameOptionsValue string
	// If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
	ContentTypeNosniff bool
	// If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
	BrowserXssFilter bool
	// ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
	ContentSecurityPolicy string
	// When developing, the AllowedHosts, SSL, and STS options can cause some unwanted effects. Usually testing happens on http, not https, and on localhost, not your production domain... so set this to true for dev environment.
	// If you would like your development environment to mimic production with complete Host blocking, SSL redirects, and STS headers, leave this as false. Default if false.
	IsDevelopment bool
}

// Secure is a middleware that helps setup a few basic security features. A single secure.Options struct can be
// provided to configure which features should be enabled, and the ability to override a few of the default values.
type Secure struct {
	opt Options
}

// NewSecure returns a new Secure instance.
func NewSecure(opt Options) *Secure {
	return &Secure{
		opt: opt,
	}
}

func (s *Secure) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Allowed hosts check.
	if len(s.opt.AllowedHosts) > 0 && s.opt.IsDevelopment == false {
		isGoodHost := false
		for _, allowedHost := range s.opt.AllowedHosts {
			if strings.EqualFold(allowedHost, r.Host) {
				isGoodHost = true
				break
			}
		}

		if isGoodHost == false {
			http.Error(rw, "Bad Host", http.StatusInternalServerError)
		}
	}

	// SSL check.
	if s.opt.SSLRedirect && s.opt.IsDevelopment == false {
		isSSL := false
		if strings.EqualFold(r.URL.Scheme, "https") || r.TLS != nil {
			isSSL = true
		} else {
			for hKey, hVal := range s.opt.SSLProxyHeaders {
				if r.Header.Get(hKey) == hVal {
					isSSL = true
					break
				}
			}
		}

		if isSSL == false {
			url := r.URL
			url.Scheme = "https"
			url.Host = r.Host

			if len(s.opt.SSLHost) > 0 {
				url.Host = s.opt.SSLHost
			}

			http.Redirect(rw, r, url.String(), http.StatusMovedPermanently)
		}
	}

	// Strict Transport Security header.
	if s.opt.STSSeconds != 0 && s.opt.IsDevelopment == false {
		stsSub := ""
		if s.opt.STSIncludeSubdomains {
			stsSub = stsSubdomainString
		}

		rw.Header().Add(stsHeader, fmt.Sprintf("max-age=%d%s", s.opt.STSSeconds, stsSub))
	}

	// Frame Options header.
	if s.opt.CustomFrameOptionsValue != "" {
		rw.Header().Add(frameOptionsHeader, s.opt.CustomFrameOptionsValue)
	} else if s.opt.FrameDeny {
		rw.Header().Add(frameOptionsHeader, frameOptionsValue)
	}

	// Content Type Options header.
	if s.opt.ContentTypeNosniff {
		rw.Header().Add(contentTypeHeader, contentTypeValue)
	}

	// XSS Protection header.
	if s.opt.BrowserXssFilter {
		rw.Header().Add(xssProtectionHeader, xssProtectionValue)
	}

	// Content Security Policy header.
	if s.opt.ContentSecurityPolicy != "" {
		rw.Header().Add(cspHeader, s.opt.ContentSecurityPolicy)
	}

	// Continue.
	next(rw, r)
}
