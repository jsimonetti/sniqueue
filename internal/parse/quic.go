package parse

import (
	"bytes"

	"github.com/jsimonetti/sniqueue/internal/parse/quic"
)

type Quic struct {
	Header *quic.ExtendedHeader
	Hello  quickHelloMsg
}

func (p *Quic) unmarshal(payload []byte) error {
	hdr, err := quic.ParseHeader(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	if int64(len(payload)) < hdr.ParsedLen+hdr.Length {
		return quic.UnmarshalQUICError
	}

	opener := quic.NewInitialAEAD(hdr.DestConnectionID, hdr.Version)
	encryptedData := payload[:hdr.ParsedLen+hdr.Length]
	p.Header, err = quic.UnpackHeader(opener, hdr, encryptedData, hdr.Version)
	if err != nil {
		return err
	}

	hdrLen := p.Header.ParsedLen
	var decryptedData []byte
	if decryptedData, err = opener.Open(encryptedData[hdrLen:hdrLen], encryptedData[hdrLen:], p.Header.PacketNumber, encryptedData[:hdrLen]); err != nil {
		return err
	}

	frameHeaderSize := 4
	return p.Hello.unmarshal(decryptedData[frameHeaderSize:])
}
