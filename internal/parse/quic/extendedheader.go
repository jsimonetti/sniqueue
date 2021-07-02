package quic

import (
	"bytes"
	"fmt"
	"io"
)

// ExtendedHeader is the header of a QUIC packet.
type ExtendedHeader struct {
	Header

	KeyPhase uint8

	PacketNumberLen uint8
	PacketNumber    int64
}

func (h *ExtendedHeader) Parse(b *bytes.Reader, v uint32) (bool /* reserved bits valid */, error) {
	startLen := b.Len()
	// read the (now unencrypted) first byte
	var err error
	h.TypeByte, err = b.ReadByte()
	if err != nil {
		return false, err
	}
	if _, err := b.Seek(int64(h.Header.ParsedLen)-1, io.SeekCurrent); err != nil {
		return false, err
	}
	reservedBitsValid, err := h.parseLongHeader(b, v)
	if err != nil {
		return false, err
	}

	h.ParsedLen = int64(startLen - b.Len())
	return reservedBitsValid, err
}

func (h *ExtendedHeader) parseLongHeader(b *bytes.Reader, _ uint32) (bool /* reserved bits valid */, error) {
	if err := h.readPacketNumber(b); err != nil {
		return false, err
	}
	if h.TypeByte&0xc != 0 {
		return false, nil
	}
	return true, nil
}

func (h *ExtendedHeader) readPacketNumber(b *bytes.Reader) error {
	h.PacketNumberLen = uint8(h.TypeByte&0x3) + 1
	switch h.PacketNumberLen {
	case 1:
		n, err := b.ReadByte()
		if err != nil {
			return err
		}
		h.PacketNumber = int64(n)
	case 2:
		n, err := ReadUint16(b)
		if err != nil {
			return err
		}
		h.PacketNumber = int64(n)
	case 3:
		n, err := ReadUint24(b)
		if err != nil {
			return err
		}
		h.PacketNumber = int64(n)
	case 4:
		n, err := ReadUint32(b)
		if err != nil {
			return err
		}
		h.PacketNumber = int64(n)
	default:
		return fmt.Errorf("invalid packet number length: %d", h.PacketNumberLen)
	}
	return nil
}
