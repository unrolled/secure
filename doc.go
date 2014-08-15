/*Package secure is an http middleware for Go that facilitates some quick security wins.

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
          AllowedHosts: []string{"www.example.com", "sub.example.com"},
          SSLRedirect:  true,
      })

      app := secureMiddleware.Handler(myHandler)
      http.ListenAndServe("0.0.0.0:3000", app)
  }
*/
package secure
