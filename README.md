# secure

Negroni middleware that helps enable some quick security wins.

[API Reference](http://godoc.org/github.com/unrolled/negroni-secure)

## Usage

```go
package main

import (
  "fmt"
  "net/http"

  "github.com/codegangsta/negroni"
  "github.com/unrolled/negroni-secure/secure"
)

func main() {
  mux := http.NewServeMux()
  mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
    fmt.Fprintf(w, "Welcome to the home page!")
  })

  n := negroni.Classic()
  n.UseHandler(mux)
  n.Use(secure.NewSecure(secure.Options{
    AllowedHosts: []string{"example.com", "ssl.example.com"},
    SSLRedirect: true,
    SSLHost: "ssl.example.com",
    SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"},
    STSSeconds: 315360000,
    STSIncludeSubdomains: true,
    FrameDeny: true,
    ContentTypeNosniff: true,
    BrowserXssFilter: true,
    ContentSecurityPolicy: "default-src 'self'",
  }))
  n.Run(":3000")
}
```

Make sure to include the secure middleware as close to the top as possible. It's best to do the allowed hosts and SSL check before anything else.

The above example will only allow requests with a host name of 'example.com', or 'ssl.example.com'. Also if the request is not https, it will be redirected to https with the host name of 'ssl.example.com'.
After this it will add the following headers:
```
Strict-Transport-Security: 315360000; includeSubdomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

###Set the `IsDevelopment` option to `true` when developing.
If you don't, the AllowedHosts, SSLRedirect, and STS Header will not be in effect. This allows you to work in development/test mode and not have any annoying redirects to HTTPS (ie. development can happen on http), or block `localhost` has a bad host.


### Options
`secure.Secure` comes with a variety of configuration options:

```go
// ...
n.Use(secure.NewSecure(secure.Options{
  AllowedHosts: []string{"ssl.example.com"}, // AllowedHosts is a list of fully qualified domain names that are allowed. Default is empty list, which allows any and all host names.
  SSLRedirect: true, // If SSLRedirect is set to true, then only allow https requests. Default is false.
  SSLHost: "ssl.example.com", // SSLHost is the host name that is used to redirect http requests to https. Default is "", which indicates to use the same host.
  SSLProxyHeaders: map[string]string{"X-Forwarded-Proto": "https"}, // SSLProxyHeaders is set of header keys with associated values that would indicate a valid https request. Useful when using Nginx: `map[string]string{"X-Forwarded-Proto": "https"}`. Default is blank map.
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
```

### Redirecting HTTP to HTTPS
If you want to redirect all http requests to https, you can use the following example. Note that the `martini.Env` needs to be in production, otherwise the redirect will not happen (see the `MARTINI_ENV` section above for other ways around this).

```go
package main

import (
  "fmt"
  "log"
  "net/http"

  "github.com/codegangsta/negroni"
  "github.com/unrolled/negroni-secure/secure"
)

func main() {
  mux := http.NewServeMux()
  mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
    fmt.Fprintf(w, "Welcome to the home page!")
  })

  n := negroni.Classic()
  n.UseHandler(mux)
  n.Use(secure.NewSecure(secure.Options{
    SSLRedirect:  true,
    SSLHost:      "localhost:8443",  // This is optional in production. The default behavior is to just redirect the request to the https protocol. Example: http://github.com/some_page would be redirected to https://github.com/some_page.
  }))


  // HTTP
  go func() {
    log.Fatal(http.ListenAndServe(":8080", n))
  }()

  // HTTPS
  // To generate a development cert and key, run the following from your *nix terminal:
  // go run $GOROOT/src/pkg/crypto/tls/generate_cert.go --host="localhost"
  log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", n))
}
```

### Nginx
If you would like to add the above security rules directly to your nginx configuration, everything is below:
```
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
```

## Authors
* [Cory Jacobsen](http://github.com/unrolled)
