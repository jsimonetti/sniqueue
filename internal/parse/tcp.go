package parse

import (
	"encoding/binary"
	"errors"
)

var unmarshalTCPError = errors.New("insufficient bytes to unmarshal TCP")

type TCP struct {
	SourcePort      uint16
	DestinationPort uint16
	Hello           clientHello
}

func (p *TCP) domainName() string {
	return p.Hello.SNI
}

func (p *TCP) unmarshal(payload []byte) error {
	// add code to skip SYN, SYN/ACK, RST, etc
	if len(payload) < 20 { // truncated / fragmented packet
		return unmarshalTCPError
	}

	p.SourcePort = binary.BigEndian.Uint16(payload[:2])
	p.DestinationPort = binary.BigEndian.Uint16(payload[2:4])

	dataOffset := int(payload[12] >> 4)
	if dataOffset < 5 {
		// Invalid TCP data offset
		return unmarshalTCPError
	}

	cursor := int(dataOffset) * 4
	if cursor >= len(payload) {
		// TCP data offset greater than packet length
		return unmarshalTCPError
	}

	// Only handle TLS
	if payload[cursor] == 0x16 {
		return p.Hello.unmarshal(payload[cursor:])
	}
	return nil
}
