package parse

import (
	"encoding/binary"
	"errors"
	"net"
)

type IPv4 struct {
	IP
}

type IPv6 struct {
	IP
}

type IP struct {
	Cursor         int
	IPVersion      int
	IPHeaderLength int
	Length         uint16
	Protocol       int
	Source         net.IP
	Destination    net.IP
	Transport      transportLayer
}

func (p *IP) DomainName() string {
	if p.Transport != nil {
		return p.Transport.domainName()
	}
	return ""
}

type transportLayer interface {
	unmarshal([]byte) error
	domainName() string
}

func (p *IPv4) unmarshal(payload []byte) error {
	p.Source = payload[12:16]
	p.Destination = payload[16:20]
	p.Protocol = int(payload[9])
	p.Length = binary.BigEndian.Uint16(payload[2:4])

	// This code is added for the following enviroment:
	// * Windows 10 with TSO option activated. ( tested on Hyper-V, RealTek ethernet driver )
	if p.Length == 0 {
		// If using TSO(TCP Segmentation Offload), length is zero.
		// The actual packet length is the length of data.
		p.Length = uint16(len(payload))
	}

	if p.Length < 20 {
		// Invalid (too small) IP length
		return unmarshalInsufficientError
	} else if p.IPHeaderLength < 5 {
		// Invalid (too small) IP header length
		return unmarshalInsufficientError
	} else if int(p.IPHeaderLength*4) > int(p.Length) {
		// Invalid IP header length > IP length
		return unmarshalInsufficientError
	}

	switch p.Protocol {
	case 6:
		p.Transport = &TCP{}
		return p.Transport.unmarshal(payload[p.IPHeaderLength*4:])
	case 17:
		p.Transport = &UDP{}
		return p.Transport.unmarshal(payload[p.IPHeaderLength*4:])
	}

	return unmarshalInsufficientError
}

func (p *IPv6) unmarshal(payload []byte) error {
	if len(payload) < 40 {
		return unmarshalInsufficientError
	}
	p.Source = payload[8:24]
	p.Destination = payload[24:40]
	p.Protocol = int(payload[6])
	p.Length = binary.BigEndian.Uint16(payload[4:6])

	var t transportLayer
	switch p.Protocol {
	case 6:
		t = &TCP{}
	case 17:
		t = &UDP{}
	}

	return t.unmarshal(payload[40:])
}

type networkLayer interface {
	unmarshal([]byte) error
	DomainName() string
}

var networkUnmarshalError = errors.New("could not unmarshal as IP")

func Parse(payload []byte) (networkLayer, error) {
	if len(payload) < 1 {
		return nil, unmarshalInsufficientError
	}

	version := int(payload[0]) >> 4
	headerLength := int(payload[0]) & 0x0F

	var p networkLayer
	switch version {
	case 4: // IPv4
		p = &IPv4{
			IP{
				IPVersion:      4,
				IPHeaderLength: headerLength,
			},
		}
		return p, p.unmarshal(payload)
	case 6: // IPv6
		p = &IPv6{
			IP{
				IPVersion:      6,
				IPHeaderLength: headerLength,
			},
		}
		return p, p.unmarshal(payload)
	}
	return nil, unmarshalInsufficientError
}
