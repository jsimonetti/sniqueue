package parse

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jsimonetti/sniqueue/internal/parse/quic"
	"github.com/jsimonetti/sniqueue/internal/parse/tls"
)

var unmarshalUDPError = errors.New("insufficient bytes to Unmarshal UDP")
var errTruncatedPacket = errors.New("truncated packet")

type UDP struct {
	SourcePort      uint16
	DestinationPort uint16
	Hello           tls.ClientHello
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
		return fmt.Errorf("%s %d > %d", errTruncatedPacket, length, len(payload))
	}

	quick := &quic.Quic{}
	if err := quick.Unmarshal(payload[8:]); err != nil {
		return err
	}
	p.Hello.SNI = quick.Hello.SNI
	return nil
}
