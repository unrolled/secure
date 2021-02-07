# Secure [![GoDoc](https://godoc.org/github.com/unrolled/secure?status.svg)](http://godoc.org/github.com/unrolled/secure) [![Test](https://github.com/unrolled/secure/workflows/Test/badge.svg?branch=v1)](https://github.com/unrolled/secure/actions)

Secure is an HTTP middleware for Go that facilitates some quick security wins. It's a standard net/http [Handler](http://golang.org/pkg/net/http/#Handler), and can be used with many [frameworks](#integration-examples) or directly with Go's net/http package.

## Usage

~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("hello world"))
})

func main() {
    secureMiddleware := secure.New(secure.Options{
        AllowedHosts:          []string{"example\\.com", ".*\\.example\\.com"},
        AllowedHostsAreRegex:  true,
        HostsProxyHeaders:     []string{"X-Forwarded-Host"},
        SSLRedirect:           true,
        SSLHost:               "ssl.example.com",
        SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
        STSSeconds:            31536000,
        STSIncludeSubdomains:  true,
        STSPreload:            true,
        FrameDeny:             true,
        ContentTypeNosniff:    true,
        BrowserXssFilter:      true,
        ContentSecurityPolicy: "script-src $NONCE",
    })

    app := secureMiddleware.Handler(myHandler)
    http.ListenAndServe("127.0.0.1:3000", app)
}
~~~

Be sure to include the Secure middleware as close to the top (beginning) as possible (but after logging and recovery). It's best to do the allowed hosts and SSL check before anything else.

The above example will only allow requests with a host name of 'example.com', or 'ssl.example.com'. Also if the request is not HTTPS, it will be redirected to HTTPS with the host name of 'ssl.example.com'.
Once those requirements are satisfied, it will add the following headers:
~~~ go
Strict-Transport-Security: 31536000; includeSubdomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: script-src 'nonce-a2ZobGFoZg=='
~~~

### Set the `IsDevelopment` option to `true` when developing!
When `IsDevelopment` is true, the AllowedHosts, SSLRedirect, STS header, and HPKP header will not be in effect. This allows you to work in development/test mode and not have any annoying redirects to HTTPS (ie. development can happen on HTTP), or block `localhost` has a bad host.

### Available options
Secure comes with a variety of configuration options (Note: these are not the default option values. See the defaults below.):

~~~ go
// ...
s := secure.New(secure.Options{
    AllowedHosts: []string{"ssl.example.com"}, // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
    AllowedHostsAreRegex: false,  // AllowedHostsAreRegex determines, if the provided AllowedHosts slice contains valid regular expressions. Default is false.
    HostsProxyHeaders: []string{"X-Forwarded-Hosts"}, // HostsProxyHeaders is a set of header keys that may hold a proxied hostname value for the request.
    SSLRedirect: true, // If SSLRedirect is set to true, then only allow HTTPS requests. Default is false.
    SSLTemporaryRedirect: false, // If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
    SSLHost: "ssl.example.com", // SSLHost is the host name that is used to redirect HTTP requests to HTTPS. Default is "", which indicates to use the same host.
    SSLHostFunc: nil, // SSLHostFunc is a function pointer, the return value of the function is the host name that has same functionality as `SSHost`. Default is nil. If SSLHostFunc is nil, the `SSLHost` option will be used.
    SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid HTTPS request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
    STSSeconds: 31536000, // STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
    STSIncludeSubdomains: true, // If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
    STSPreload: true, // If STSPreload is set to true, the `preload` flag will be appended to the Strict-Transport-Security header. Default is false.
    ForceSTSHeader: false, // STS header is only included when the connection is HTTPS. If you want to force it to always be added, set to true. `IsDevelopment` still overrides this. Default is false.
    FrameDeny: true, // If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
    CustomFrameOptionsValue: "SAMEORIGIN", // CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option. Default is "".
    ContentTypeNosniff: true, // If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
    BrowserXssFilter: true, // If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
    CustomBrowserXssValue: "1; report=https://example.com/xss-report", // CustomBrowserXssValue allows the X-XSS-Protection header value to be set with a custom value. This overrides the BrowserXssFilter option. Default is "".
    ContentSecurityPolicy: "default-src 'self'", // ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "". Passing a template string will replace `$NONCE` with a dynamic nonce value of 16 bytes for each request which can be later retrieved using the Nonce function.
    PublicKey: `pin-sha256="base64+primary=="; pin-sha256="base64+backup=="; max-age=5184000; includeSubdomains; report-uri="https://www.example.com/hpkp-report"`, // Deprecated: This feature is no longer recommended. PublicKey implements HPKP to prevent MITM attacks with forged certificates. Default is "".
    ReferrerPolicy: "same-origin", // ReferrerPolicy allows the Referrer-Policy header with the value to be set with a custom value. Default is "".
    FeaturePolicy: "vibrate 'none';", // Deprecated: this header has been renamed to PermissionsPolicy. FeaturePolicy allows the Feature-Policy header with the value to be set with a custom value. Default is "".
    PermissionsPolicy: "fullscreen=(), geolocation=()", // PermissionsPolicy allows the Permissions-Policy header with the value to be set with a custom value. Default is "".
    ExpectCTHeader: `enforce, max-age=30, report-uri="https://www.example.com/ct-report"`,

    IsDevelopment: true, // This will cause the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains options to be ignored during development. When deploying to production, be sure to set this to false.
})
// ...
~~~

### Default options
These are the preset options for Secure:

~~~ go
s := secure.New()

// Is the same as the default configuration options:

l := secure.New(secure.Options{
    AllowedHosts: []string,
    AllowedHostsAreRegex: false,
    HostsProxyHeaders: []string,
    SSLRedirect: false,
    SSLTemporaryRedirect: false,
    SSLHost: "",
    SSLProxyHeaders: map[string]string{},
    STSSeconds: 0,
    STSIncludeSubdomains: false,
    STSPreload: false,
    ForceSTSHeader: false,
    FrameDeny: false,
    CustomFrameOptionsValue: "",
    ContentTypeNosniff: false,
    BrowserXssFilter: false,
    ContentSecurityPolicy: "",
    PublicKey: "",
    ReferrerPolicy: "",
    FeaturePolicy: "",
    PermissionsPolicy: "",
    ExpectCTHeader: "",
    IsDevelopment: false,
})
~~~
Also note the default bad host handler returns an error:
~~~ go
http.Error(w, "Bad Host", http.StatusInternalServerError)
~~~
Call `secure.SetBadHostHandler` to change the bad host handler.

### Redirecting HTTP to HTTPS
If you want to redirect all HTTP requests to HTTPS, you can use the following example.

~~~ go
// main.go
package main

import (
    "log"
    "net/http"

    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("hello world"))
})

func main() {
    secureMiddleware := secure.New(secure.Options{
        SSLRedirect: true,
        SSLHost:     "localhost:8443", // This is optional in production. The default behavior is to just redirect the request to the HTTPS protocol. Example: http://github.com/some_page would be redirected to https://github.com/some_page.
    })

    app := secureMiddleware.Handler(myHandler)

    // HTTP
    go func() {
        log.Fatal(http.ListenAndServe(":8080", app))
    }()

    // HTTPS
    // To generate a development cert and key, run the following from your *nix terminal:
    // go run $GOROOT/src/crypto/tls/generate_cert.go --host="localhost"
    log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", app))
}
~~~

### Strict Transport Security
The STS header will only be sent on verified HTTPS connections (and when `IsDevelopment` is false). Be sure to set the `SSLProxyHeaders` option if your application is behind a proxy to ensure the proper behavior. If you need the STS header for all HTTP and HTTPS requests (which you [shouldn't](http://tools.ietf.org/html/rfc6797#section-7.2)), you can use the `ForceSTSHeader` option. Note that if `IsDevelopment` is true, it will still disable this header even when `ForceSTSHeader` is set to true.

* The `preload` flag is required for domain inclusion in Chrome's [preload](https://hstspreload.appspot.com/) list.

### Content Security Policy
If you need dynamic support for CSP while using Websockets, check out this other middleware [awakenetworks/csp](https://github.com/awakenetworks/csp).

## Integration examples

### [chi](https://github.com/pressly/chi)
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/pressly/chi"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    r := chi.NewRouter()
    r.Use(secureMiddleware.Handler)

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("X-Frame-Options header is now `DENY`."))
    })

    http.ListenAndServe("127.0.0.1:3000", r)
}
~~~

### [Echo](https://github.com/labstack/echo)
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/labstack/echo"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    e := echo.New()
    e.GET("/", func(c echo.Context) error {
        return c.String(http.StatusOK, "X-Frame-Options header is now `DENY`.")
    })

    e.Use(echo.WrapMiddleware(secureMiddleware.Handler))
    e.Logger.Fatal(e.Start("127.0.0.1:3000"))
}
~~~

### [Gin](https://github.com/gin-gonic/gin)
~~~ go
// main.go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })
    secureFunc := func() gin.HandlerFunc {
        return func(c *gin.Context) {
            err := secureMiddleware.Process(c.Writer, c.Request)

            // If there was an error, do not continue.
            if err != nil {
                c.Abort()
                return
            }

            // Avoid header rewrite if response is a redirection.
            if status := c.Writer.Status(); status > 300 && status < 399 {
                c.Abort()
            }
        }
    }()

    router := gin.Default()
    router.Use(secureFunc)

    router.GET("/", func(c *gin.Context) {
        c.String(200, "X-Frame-Options header is now `DENY`.")
    })

    router.Run("127.0.0.1:3000")
}
~~~

### [Goji](https://github.com/zenazn/goji)
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
    "github.com/zenazn/goji"
    "github.com/zenazn/goji/web"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    goji.Get("/", func(c web.C, w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("X-Frame-Options header is now `DENY`."))
    })
    goji.Use(secureMiddleware.Handler)
    goji.Serve() // Defaults to ":8000".
}
~~~

### [Iris](https://github.com/kataras/iris)
~~~ go
//main.go
package main

import (
    "github.com/kataras/iris/v12"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    app := iris.New()

    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    app.Use(iris.FromStd(secureMiddleware.HandlerFuncWithNext))
    // Identical to:
    // app.Use(func(ctx iris.Context) {
    //     err := secureMiddleware.Process(ctx.ResponseWriter(), ctx.Request())
    //
    //     // If there was an error, do not continue.
    //     if err != nil {
    //         return
    //     }
    //
    //     ctx.Next()
    // })

    app.Get("/home", func(ctx iris.Context) {
        ctx.Writef("X-Frame-Options header is now `%s`.", "DENY")
    })

    app.Listen(":8080")
}
~~~

### [Mux](https://github.com/gorilla/mux)
~~~ go
//main.go
package main

import (
    "log"
    "net/http"

    "github.com/gorilla/mux"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    r := mux.NewRouter()
    r.Use(secureMiddleware.Handler)
    http.Handle("/", r)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", 8080), nil))
}
~~~

### [Negroni](https://github.com/urfave/negroni)
Note this implementation has a special helper function called `HandlerFuncWithNext`.
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/urfave/negroni"
    "github.com/unrolled/secure" // or "gopkg.in/unrolled/secure.v1"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("X-Frame-Options header is now `DENY`."))
    })

    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    n := negroni.Classic()
    n.Use(negroni.HandlerFunc(secureMiddleware.HandlerFuncWithNext))
    n.UseHandler(mux)

    n.Run("127.0.0.1:3000")
}
~~~
