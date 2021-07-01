package parse

import (
	"encoding/binary"
	"errors"
)

var unmarshalUDPError = errors.New("insufficient bytes to unmarshal UDP")

type UDP struct {
	SourcePort      uint16
	DestinationPort uint16
	Hello           clientHello
}

func (p *UDP) domainName() string {
	return p.Hello.SNI
}

func (p *UDP) unmarshal(payload []byte) error {
	if len(payload) < 8 { // truncated/fragmented
		return unmarshalUDPError
	}
	p.SourcePort = binary.BigEndian.Uint16(payload[0:2])
	p.DestinationPort = binary.BigEndian.Uint16(payload[2:4])
	length := int(binary.BigEndian.Uint16(payload[4:6]))

	if length < 8 { // too small packet
		return unmarshalUDPError
	}
	if length > len(payload) { // truncated/fragmented
		return unmarshalUDPError
	}

	quick := &Quic{}
	if err := quick.unmarshal(payload[8:]); err != nil {
		return err
	}
	p.Hello.SNI = quick.Hello.SNI
	return nil
}
