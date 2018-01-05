package secure

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
)

// CSPNonce returns the nonce value associated with the present request. If no nonce has been generated it returns an empty string.
func CSPNonce(c context.Context) string {
	if val, ok := c.Value(cspNonceKey).(string); ok {
		return val
	}

	return ""
}

type key int

const cspNonceKey key = iota

func cspRandNonce() string {
	var buf [cspNonceSize]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic("CSP Nonce rand.Reader failed" + err.Error())
	}

	return base64.RawStdEncoding.EncodeToString(buf[:])
}

func withCSPNonce(r *http.Request, nonce string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), cspNonceKey, nonce))
}
