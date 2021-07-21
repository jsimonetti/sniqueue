package tls

import (
	"encoding/binary"
)

type ClientHello struct {
	SNI string
}

func (m *ClientHello) Unmarshal(payload []byte) error {
	payloadLength := uint16(len(payload))
	if payloadLength < uint16(4) {
		return UnmarshalClientHelloError
	}

	handshakeProtocol := payload[4]
	// Only attempt to match on client hellos
	if handshakeProtocol != 0x01 {
		// test for GQUIC
		if payloadLength >= 16 {
			if payload[4] == 0x43 && payload[5] == 0x48 && payload[6] == 0x4c && payload[7] == 0x4f { // GQUIC's CHLO
				//tagNum := binary.BigEndian.Uint16(payload[8:10]) // total number of variable length tags
				tagNum := uint16(payload[8]) + uint16(payload[9])<<8
				tagOffset := 12 // start of the first tag
				payloadLength := int(payloadLength)

				for tagNum > 0 && payloadLength >= tagOffset+8 {
					tagType := binary.LittleEndian.Uint32(payload[tagOffset : tagOffset+4])
					if tagType == 4804179 {
						tagLen := binary.LittleEndian.Uint32(payload[tagOffset+4 : tagOffset+8])
						tagStart := tagOffset + int(tagNum)*8
						tagEnd := tagStart + int(tagLen)
						if payloadLength > tagOffset+int(tagNum)*8+tagEnd {
							m.SNI = string(payload[tagStart:tagEnd])
							return nil
						}
						tagOffset = tagOffset + 8
					}
					tagNum--
				}
				return UnmarshalNoTLSHandshakeError
			}
		}
		return UnmarshalNoTLSHandshakeError
	}

	offset, baseOffset, extensionOffset := uint16(0), uint16(42), uint16(2)
	if baseOffset+2 > payloadLength {
		return UnmarshalClientHelloError
	}

	// Get the length of the session ID
	sessionIDLength := uint16(payload[baseOffset])
	if (sessionIDLength + baseOffset + 2) > payloadLength {
		return UnmarshalClientHelloError
	}

	// Get the length of the ciphers
	cipherLenStart := baseOffset + sessionIDLength + 1
	cipherLen := binary.BigEndian.Uint16(payload[cipherLenStart : cipherLenStart+2])

	offset = baseOffset + sessionIDLength + cipherLen + 2
	if offset > payloadLength {
		return UnmarshalClientHelloError
	}

	// Get the length of the compression methods list
	compressionLen := uint16(payload[offset+1])
	offset += compressionLen + 2
	if offset > payloadLength {
		return UnmarshalClientHelloError
	}

	// Get the length of the extensions
	extensionsLen := binary.BigEndian.Uint16(payload[offset : offset+2])

	// Add the full offset to were the extensions start
	extensionOffset += offset

	if extensionsLen > payloadLength {
		return UnmarshalClientHelloError
	}

	for extensionOffset < extensionsLen+offset {
		extensionID := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
		extensionOffset += 2

		extensionLen := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
		extensionOffset += 2

		if extensionID == 0 {
			// We don't need the server name list length or name_type, so skip that
			extensionOffset += 3

			// Get the length of the domain name
			nameLength := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
			extensionOffset += 2

			m.SNI = string(payload[extensionOffset : extensionOffset+nameLength])
			return nil
		}
		extensionOffset += extensionLen
	}
	return nil
}
