# Secure [![GoDoc](https://godoc.org/github.com/unrolled/secure?status.png)](http://godoc.org/github.com/unrolled/secure)

Secure is an HTTP middleware for Go that facilitates some quick security wins.

## Usage

~~~ go
// main.go
package main

import (
    "net/http"

    "gopkg.in/unrolled/secure.v1"
)

func myApp(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello world!"))
}

func main() {
    myHandler := http.HandlerFunc(myApp)

    secureMiddleware := secure.New(secure.Options{
        AllowedHosts:          []string{"example.com", "ssl.example.com"},
        SSLRedirect:           true,
        SSLHost:               "ssl.example.com",
        SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
        STSSeconds:            315360000,
        STSIncludeSubdomains:  true,
        FrameDeny:             true,
        ContentTypeNosniff:    true,
        BrowserXssFilter:      true,
        ContentSecurityPolicy: "default-src 'self'",
    })

    app := secureMiddleware.Handler(myHandler)
    http.ListenAndServe("0.0.0.0:3000", app)
}
~~~

Make sure to include the secure middleware as close to the top (beginning) as possible. It's best to do the allowed hosts and SSL check before anything else.

The above example will only allow requests with a host name of 'example.com', or 'ssl.example.com'. Also if the request is not HTTPS, it will be redirected to HTTPS with the host name of 'ssl.example.com'.
Once those requirements are satisfied, it will add the following headers:
~~~ go
Strict-Transport-Security: 315360000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
~~~

###Set the `IsDevelopment` option to `true` when developing.
When `IsDevelopment` is true, the AllowedHosts, SSLRedirect, and STS Header will not be in effect. This allows you to work in development/test mode and not have any annoying redirects to HTTPS (ie. development can happen on HTTP), or block `localhost` has a bad host.


### Options
`secure.Options` comes with a variety of configuration settings:

~~~ go
// ...
secureMiddleware := secure.New(secure.Options{
    AllowedHosts: []string{"ssl.example.com"}, // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
    SSLRedirect: true, // If SSLRedirect is set to true, then only allow HTTPS requests. Default is false.
    SSLTemporaryRedirect: false, // If SSLTemporaryRedirect is true, the a 302 will be used while redirecting. Default is false (301).
    SSLHost: "ssl.example.com", // SSLHost is the host name that is used to redirect HTTP requests to HTTPS. Default is "", which indicates to use the same host.
    SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid HTTPS request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
    STSSeconds: 315360000, // STSSeconds is the max-age of the Strict-Transport-Security header. Default is 0, which would NOT include the header.
    STSIncludeSubdomains: true, // If STSIncludeSubdomains is set to true, the `includeSubdomains` will be appended to the Strict-Transport-Security header. Default is false.
    FrameDeny: true, // If FrameDeny is set to true, adds the X-Frame-Options header with the value of `DENY`. Default is false.
    CustomFrameOptionsValue: "SAMEORIGIN", // CustomFrameOptionsValue allows the X-Frame-Options header value to be set with a custom value. This overrides the FrameDeny option.
    ContentTypeNosniff: true, // If ContentTypeNosniff is true, adds the X-Content-Type-Options header with the value `nosniff`. Default is false.
    BrowserXssFilter: true, // If BrowserXssFilter is true, adds the X-XSS-Protection header with the value `1; mode=block`. Default is false.
    ContentSecurityPolicy: "default-src 'self'", // ContentSecurityPolicy allows the Content-Security-Policy header value to be set with a custom value. Default is "".
    IsDevelopment: true, // This will cause the AllowedHosts, SSLRedirect, and STSSeconds/STSIncludeSubdomains options to be ignored during development. When deploying to production, be sure to set this to false.
}))
// ...
~~~

### Redirecting HTTP to HTTPS
If you want to redirect all HTTP requests to HTTPS, you can use the following example.

~~~ go
// main.go
package main

import (
    "log"
    "net/http"

    "gopkg.in/unrolled/secure.v1"
)

func myApp(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello world!"))
}

func main() {
    myHandler := http.HandlerFunc(myApp)

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
    // go run $GOROOT/src/pkg/crypto/tls/generate_cert.go --host="localhost"
    log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", app))
}
~~~

## Integration Examples

### [Goji](https://github.com/zenazn/goji)
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/zenazn/goji"
    "github.com/zenazn/goji/web"
    "gopkg.in/unrolled/secure.v1"
)

func main() {
    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    goji.Get("/", func(c web.C, w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("X-Frame-Options header should be `DENY`."))
    })
    goji.Use(secureMiddleware.Handler)
    goji.Serve() // Defaults to ":8000".
}
~~~

### [Negroni](https://github.com/codegangsta/negroni)
Note this implementation has a special helper function called `HandlerFuncWithNext`.
~~~ go
// main.go
package main

import (
    "net/http"

    "github.com/codegangsta/negroni"
    "gopkg.in/unrolled/secure.v1"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
        w.Write([]byte("X-Frame-Options header should be `DENY`."))
    })

    secureMiddleware := secure.New(secure.Options{
        FrameDeny: true,
    })

    n := negroni.Classic()
    n.Use(negroni.HandlerFunc(secureMiddleware.HandlerFuncWithNext))
    n.UseHandler(mux)

    n.Run("0.0.0.0:3000")
}
~~~


## Nginx
If you would like to add the above security rules directly to your nginx configuration, everything is below:
~~~
# Allowed Hosts:
if ($host !~* ^(example.com|ssl.example.com)$ ) {
    return 500;
}

# SSL Redirect:
server {
    listen      80;
    server_name example.com ssl.example.com;
    return 301 https://ssl.example.com$request_uri;
}

# Headers to be added:
add_header Strict-Transport-Security "max-age=315360000";
add_header X-Frame-Options "DENY";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'";
~~~
