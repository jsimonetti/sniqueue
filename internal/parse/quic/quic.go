package quic

import (
	"bytes"

	"github.com/jsimonetti/sniqueue/internal/parse/tls"
)

type Quic struct {
	Header *ExtendedHeader
	Hello  tls.QuickHelloMsg
}

func (p *Quic) Unmarshal(payload []byte) error {
	hdr, err := ParseHeader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if int64(len(payload)) < hdr.ParsedLen+hdr.Length {
		return UnmarshalQUICError
	}

	opener := NewInitialAEAD(hdr.DestConnectionID, hdr.Version)
	encryptedData := payload[:hdr.ParsedLen+hdr.Length]
	p.Header, err = UnpackHeader(opener, hdr, encryptedData, hdr.Version)
	if err != nil {
		return err
	}

	hdrLen := p.Header.ParsedLen
	var decryptedData []byte
	if decryptedData, err = opener.Open(encryptedData[hdrLen:hdrLen], encryptedData[hdrLen:], p.Header.PacketNumber, encryptedData[:hdrLen]); err != nil {
		return err
	}

	frameHeaderSize := 4
	return p.Hello.Unmarshal(decryptedData[frameHeaderSize:])
}
