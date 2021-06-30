package parse

import (
	"encoding/binary"
	"errors"
	"net"
)

var unmarshalIPError = errors.New("insufficient bytes to unmarshal IP")
var unmarshalIP4Error = errors.New("insufficient bytes to unmarshal IP4")
var unmarshalIP6Error = errors.New("insufficient bytes to unmarshal IP6")
var unmarshalNonIPError = errors.New("cannot parse non-IP")

type IPv4 struct {
	Inet
}

type IPv6 struct {
	Inet
}

type Inet struct {
	IPVersion      int
	IPHeaderLength int
	Length         uint16
	Protocol       int
	Source         net.IP
	Destination    net.IP
	Transport      transportLayer
}

func (p *Inet) DomainName() string {
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
		return unmarshalIP4Error
	} else if p.IPHeaderLength < 5 {
		// Invalid (too small) IP header length
		return unmarshalIP4Error
	} else if int(p.IPHeaderLength*4) > int(p.Length) {
		// Invalid IP header length > IP length
		return unmarshalIP4Error
	}

	switch p.Protocol {
	case 6:
		p.Transport = &TCP{}
		return p.Transport.unmarshal(payload[p.IPHeaderLength*4:])
	case 17:
		p.Transport = &UDP{}
		return p.Transport.unmarshal(payload[p.IPHeaderLength*4:])
	}
	return unmarshalNonIPError
}

func (p *IPv6) unmarshal(payload []byte) error {
	if len(payload) < 40 {
		return unmarshalIP6Error
	}
	p.Source = payload[8:24]
	p.Destination = payload[24:40]
	p.Protocol = int(payload[6])
	p.Length = binary.BigEndian.Uint16(payload[4:6])

	var t transportLayer
	switch p.Protocol {
	case 6:
		p.Transport = &TCP{}
		return p.Transport.unmarshal(payload[40:])
	case 17:
		p.Transport = &UDP{}
		return p.Transport.unmarshal(payload[40:])
	}

	return t.unmarshal(payload[40:])
}

type networkLayer interface {
	unmarshal([]byte) error
	DomainName() string
}

func Parse(payload []byte) (networkLayer, error) {
	if len(payload) < 1 {
		return nil, unmarshalIPError
	}

	version := int(payload[0]) >> 4
	headerLength := int(payload[0]) & 0x0F

	var p networkLayer
	switch version {
	case 4: // IPv4
		p = &IPv4{
			Inet{
				IPVersion:      4,
				IPHeaderLength: headerLength,
			},
		}
		return p, p.unmarshal(payload)
	case 6: // IPv6
		p = &IPv6{
			Inet{
				IPVersion:      6,
				IPHeaderLength: headerLength,
			},
		}
		return p, p.unmarshal(payload)
	}
	return nil, unmarshalNonIPError
}
