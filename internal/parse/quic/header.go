package quic

import (
	"bytes"
	"io"
)

func ParseHeader(b *bytes.Reader) (*Header, error) {
	startLen := b.Len()
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}

	h := &Header{
		TypeByte:     typeByte,
		IsLongHeader: typeByte&0x80 > 0,
	}
	if !h.IsLongHeader {
		return nil, UnmarshalQUICError
	}

	err = h.parseLongHeader(b)
	h.ParsedLen = int64(startLen - b.Len())
	return h, err
}

type Header struct {
	TypeByte     byte
	IsLongHeader bool

	ParsedLen int64

	Version          uint32
	DestConnectionID []byte
	SrcConnectionID  []byte

	Length int64
	Token  []byte
}

// ParseExtended parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) ParseExtended(b *bytes.Reader, ver uint32) (*ExtendedHeader, error) {
	extHdr := h.toExtendedHeader()
	reservedBitsValid, err := extHdr.Parse(b, ver)
	if err != nil {
		return nil, err
	}
	if !reservedBitsValid {
		return extHdr, UnmarshalQUICBitsError
	}
	return extHdr, nil
}

func (h *Header) toExtendedHeader() *ExtendedHeader {
	return &ExtendedHeader{Header: *h}
}

func (h *Header) parseLongHeader(b *bytes.Reader) (err error) {
	h.Version, err = ReadUint32(b)
	if err != nil {
		return err
	}
	if h.Version != 0 && h.TypeByte&0x40 == 0 {
		return UnmarshalNoQUICError
	}
	if h.Version == 0 { // version negotiation packet
		return UnmarshalNoQUICInitialError
	}

	destConnIDLen, err := b.ReadByte()
	if err != nil {
		return err
	}
	if h.DestConnectionID, err = ReadConnectionID(b, int(destConnIDLen)); err != nil {
		return err
	}
	srcConnIDLen, err := b.ReadByte()
	if err != nil {
		return err
	}
	if h.SrcConnectionID, err = ReadConnectionID(b, int(srcConnIDLen)); err != nil {
		return err
	}

	// If we don't understand the version, we have no idea how to interpret the rest of the bytes
	if !IsSupportedVersion(SupportedVersions, h.Version) {
		return UnmarshalNoQUICError
	}
	if (h.TypeByte&0x30)>>4 != 0x0 {
		// not an initial package
		return UnmarshalNoQUICInitialError
	}

	tokenLen, err := ReadQuickVarInt(b)
	if err != nil {
		return err
	}
	if tokenLen > uint64(b.Len()) {
		return io.EOF
	}
	h.Token = make([]byte, tokenLen)
	if _, err := io.ReadFull(b, h.Token); err != nil {
		return err
	}

	pl, err := ReadQuickVarInt(b)
	if err != nil {
		return err
	}
	h.Length = int64(pl)
	return nil
}
