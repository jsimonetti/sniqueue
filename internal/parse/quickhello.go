package parse

import (
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

type quickHelloMsg struct {
	SNI string
}

func (m *quickHelloMsg) unmarshal(data []byte) error {
	s := cryptobyte.String(data)
	var u16 uint16
	var u8 []byte
	var random []byte
	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&u16) || !s.ReadBytes(&random, 32) ||
		!readUint8LengthPrefixed(&s, &u8) {
		return UnmarshalNoTLSHandshakeError
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return UnmarshalNoTLSHandshakeError
	}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return UnmarshalNoTLSHandshakeError
		}
	}

	if !readUint8LengthPrefixed(&s, &u8) {
		return UnmarshalNoTLSHandshakeError
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return nil
	}

	var extensions cryptobyte.String
	//if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
	//	return errors.New("hier")
	//}
	s.ReadUint16LengthPrefixed(&extensions)

	for !extensions.Empty() {
		var ext uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&ext) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return UnmarshalNoTLSHandshakeError
		}

		switch ext {
		case 0:
			// RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return UnmarshalNoTLSHandshakeError
			}
			for !nameList.Empty() {
				var nameType uint8
				var serverName cryptobyte.String
				if !nameList.ReadUint8(&nameType) ||
					!nameList.ReadUint16LengthPrefixed(&serverName) ||
					serverName.Empty() {
					return UnmarshalNoTLSHandshakeError
				}
				if nameType != 0 {
					continue
				}
				if len(m.SNI) != 0 {
					// Multiple names of the same name_type are prohibited.
					return UnmarshalNoTLSHandshakeError
				}
				m.SNI = string(serverName)
				// An SNI value may not include a trailing dot.
				if strings.HasSuffix(m.SNI, ".") {
					return UnmarshalNoTLSHandshakeError
				}
			}
		default:
			continue
		}

		if !extData.Empty() {
			return UnmarshalNoTLSHandshakeError
		}
	}

	return nil
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}
