package tls

import "errors"

var UnmarshalNoTLSHandshakeError = errors.New("TLS handshake not found")
var UnmarshalNoTLSError = errors.New("not a TLS packet")
var UnmarshalClientHelloError = errors.New("insufficient bytes to Unmarshal clienthello")
