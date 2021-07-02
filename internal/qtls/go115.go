// +build go1.15
// +build !go1.16

package qtls

import (
	"crypto/cipher"
	"github.com/marten-seemann/qtls-go1-15"
)

type CipherSuiteTLS13 = qtls.CipherSuiteTLS13

// AEADAESGCMTLS13 creates a new AES-GCM AEAD for TLS 1.3
func AEADAESGCMTLS13(key, fixedNonce []byte) cipher.AEAD {
	return qtls.AEADAESGCMTLS13(key, fixedNonce)
}