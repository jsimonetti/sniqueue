//go:build go1.19 && !go1.20
// +build go1.19,!go1.20

package qtls

import (
	"crypto/cipher"

	"github.com/quic-go/qtls-go1-19"
)

type CipherSuiteTLS13 = qtls.CipherSuiteTLS13

// AEADAESGCMTLS13 creates a new AES-GCM AEAD for TLS 1.3
func AEADAESGCMTLS13(key, fixedNonce []byte) cipher.AEAD {
	return qtls.AEADAESGCMTLS13(key, fixedNonce)
}
