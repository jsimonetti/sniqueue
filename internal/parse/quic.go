package parse

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/hkdf"

	"github.com/marten-seemann/qtls-go1-16"
)

var unmarshalQUICError = errors.New("insufficient bytes to unmarshal QUIC")
var unmarshalQUICDecryptError = errors.New("cannot decrypt QUIC payload")
var UnmarshalNoQUICError = errors.New("not a QUIC packet")
var UnmarshalNoQUICInitialError = errors.New("not an initial QUIC packet")
var unmarshalQUICBitsError = errors.New("unknown bits in QUIC header")

type Quic struct {
	Header  *ExtendedHeader
	Payload []byte
	Hello   quickHelloMsg
}

func (p *Quic) unmarshal(payload []byte) error {
	hdr, _, _, err := ParsePacket(payload)
	if err != nil {
		return err
	}

	initialOpener := NewInitialAEAD(hdr.DestConnectionID, hdr.Version)
	data := payload[:hdr.ParsedLen+hdr.Length]
	p.Header, err = UnpackHeader(initialOpener, hdr, data, hdr.Version)
	if err != nil {
		return err
	}
	hdrLen := p.Header.ParsedLen
	if p.Payload, err = initialOpener.Open(data[hdrLen:hdrLen], data[hdrLen:], p.Header.PacketNumber, data[:hdrLen]); err != nil {
		return err
	}
	frameHeaderSize := 4
	return p.Hello.unmarshal(p.Payload[frameHeaderSize:])
}

func UnpackHeader(hd *longHeaderOpener, hdr *Header, data []byte, version uint32) (*ExtendedHeader, error) {
	r := bytes.NewReader(data)

	hdrLen := hdr.ParsedLen
	if int64(len(data)) < hdrLen+4+16 {
		//nolint:stylecheck
		return nil, unmarshalQUICError
	}
	// The packet number can be up to 4 bytes long, but we won't know the length until we decrypt it.
	// 1. save a copy of the 4 bytes
	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])
	// 2. decrypt the header, assuming a 4 byte packet number
	hd.DecryptHeader(
		data[hdrLen+4:hdrLen+4+16],
		&data[0],
		data[hdrLen:hdrLen+4],
	)
	// 3. parse the header (and learn the actual length of the packet number)
	extHdr, parseErr := hdr.ParseExtended(r, version)
	if parseErr != nil && parseErr != unmarshalQUICBitsError {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != 4 {
		copy(data[extHdr.ParsedLen:hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}
	return extHdr, parseErr
}

// ParsePacket parses a packet.
// If the packet has a long header, the packet is cut according to the length field.
// If we understand the version, the packet is header up unto the packet number.
// Otherwise, only the invariant part of the header is parsed.
func ParsePacket(data []byte) (*Header, []byte /* packet data */, []byte /* rest */, error) {
	hdr, err := parseHeader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, nil, err
	}
	var rest []byte

	if int64(len(data)) < hdr.ParsedLen+hdr.Length {
		return nil, nil, nil, unmarshalQUICError
	}
	packetLen := hdr.ParsedLen + hdr.Length
	rest = data[packetLen:]
	data = data[:packetLen]

	return hdr, data, rest, nil
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

func parseHeader(b *bytes.Reader) (*Header, error) {
	startLen := b.Len()
	h, err := parseHeaderImpl(b)
	if err != nil {
		return h, err
	}
	h.ParsedLen = int64(startLen - b.Len())
	return h, err
}

func parseHeaderImpl(b *bytes.Reader) (*Header, error) {
	typeByte, err := b.ReadByte()
	if err != nil {
		return nil, err
	}

	h := &Header{
		TypeByte:     typeByte,
		IsLongHeader: typeByte&0x80 > 0,
	}

	if !h.IsLongHeader {
		return nil, unmarshalQUICError
	}
	return h, h.parseLongHeader(b)
}

// ParseExtended parses the version dependent part of the header.
// The Reader has to be set such that it points to the first byte of the header.
func (h *Header) ParseExtended(b *bytes.Reader, ver uint32) (*ExtendedHeader, error) {
	extHdr := h.toExtendedHeader()
	reservedBitsValid, err := extHdr.parse(b, ver)
	if err != nil {
		return nil, err
	}
	if !reservedBitsValid {
		return extHdr, unmarshalQUICBitsError
	}
	return extHdr, nil
}
func (o *longHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
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

func ReadUint32(b io.ByteReader) (uint32, error) {
	var b1, b2, b3, b4 uint8
	var err error
	if b4, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b3, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b2, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b1, err = b.ReadByte(); err != nil {
		return 0, err
	}
	return uint32(b1) + uint32(b2)<<8 + uint32(b3)<<16 + uint32(b4)<<24, nil
}

// ReadConnectionID reads a connection ID of length len from the given io.Reader.
// It returns io.EOF if there are not enough bytes to read.
func ReadConnectionID(r io.Reader, len int) ([]byte, error) {
	if len == 0 {
		return nil, nil
	}
	c := make([]byte, len)
	_, err := io.ReadFull(r, c)
	if err == io.ErrUnexpectedEOF {
		return nil, io.EOF
	}
	return c, err
}

// The version numbers, making grepping easier
const (
	VersionTLS      uint32 = 0x1
	VersionWhatever uint32 = math.MaxUint32 - 1 // for when the version doesn't matter
	VersionUnknown  uint32 = math.MaxUint32
	VersionDraft29  uint32 = 0xff00001d
	VersionDraft32  uint32 = 0xff000020
	VersionDraft34  uint32 = 0xff000022
	Version1        uint32 = 0x1
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []uint32{Version1, VersionDraft34, VersionDraft32, VersionDraft29}

// IsSupportedVersion returns true if the server supports this version
func IsSupportedVersion(supported []uint32, v uint32) bool {
	for _, t := range supported {
		if t == v {
			return true
		}
	}
	return false
}

func ReadQuickVarInt(b io.ByteReader) (uint64, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	length := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if length == 1 {
		return uint64(b1), nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if length == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if length == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

// NewInitialAEAD creates a new AEAD for Initial encryption / decryption.
func NewInitialAEAD(connID []byte, v uint32) *longHeaderOpener {
	initialSecret := hkdf.Extract(crypto.SHA256.New, connID, getSalt(v))
	clientSecret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())

	key, iv := computeInitialKeyAndIV(clientSecret)

	decrypter := qtls.AEADAESGCMTLS13(key, iv)

	return newLongHeaderOpener(decrypter, newAESHeaderProtector(initialSuite, clientSecret, true))
}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector *aesHeaderProtector) *longHeaderOpener {
	return &longHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
	}
}

type longHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector *aesHeaderProtector
	highestRcvdPN   int64 // highest packet number received (which could be successfully unprotected)

	// use a single slice to avoid allocations
	nonceBuf []byte
}

func (o *longHeaderOpener) Open(dst, src []byte, pn int64, ad []byte) ([]byte, error) {
	binary.BigEndian.PutUint64(o.nonceBuf[len(o.nonceBuf)-8:], uint64(pn))
	// The AEAD we're using here will be the qtls.aeadAESGCM13.
	// It uses the nonce provided here and XOR it with the IV.
	dec, err := o.aead.Open(dst, o.nonceBuf, src, ad)
	if err == nil {
		o.highestRcvdPN = pn
	} else {
		err = unmarshalQUICDecryptError
	}
	return dec, err
}

func newAESHeaderProtector(suite *qtls.CipherSuiteTLS13, trafficSecret []byte, isLongHeader bool) *aesHeaderProtector {
	hpKey := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic hp", suite.KeyLen)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
	return &aesHeaderProtector{
		block:        block,
		mask:         make([]byte, block.BlockSize()),
		isLongHeader: isLongHeader,
	}
}

type aesHeaderProtector struct {
	mask         []byte
	block        cipher.Block
	isLongHeader bool
}

func (p *aesHeaderProtector) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	p.apply(sample, firstByte, hdrBytes)
}

func (p *aesHeaderProtector) apply(sample []byte, firstByte *byte, hdrBytes []byte) {
	if len(sample) != len(p.mask) {
		panic("invalid sample size")
	}
	p.block.Encrypt(p.mask, sample)
	if p.isLongHeader {
		*firstByte ^= p.mask[0] & 0xf
	} else {
		*firstByte ^= p.mask[0] & 0x1f
	}
	for i := range hdrBytes {
		hdrBytes[i] ^= p.mask[i+1]
	}
}

var initialSuite = &qtls.CipherSuiteTLS13{
	ID:     tls.TLS_AES_128_GCM_SHA256,
	KeyLen: 16,
	AEAD:   qtls.AEADAESGCMTLS13,
	Hash:   crypto.SHA256,
}

// hkdfExpandLabel HKDF expands a label.
// Since this implementation avoids using a cryptobyte.Builder, it is about 15% faster than the
// hkdfExpandLabel in the standard library.
func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

func computeInitialKeyAndIV(secret []byte) (key, iv []byte) {
	key = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv = hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	return
}

var (
	quicSaltOld     = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltDraft34 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
)

func getSalt(v uint32) []byte {
	if v == VersionDraft34 || v == Version1 {
		return quicSaltDraft34
	}
	return quicSaltOld
}

// ExtendedHeader is the header of a QUIC packet.
type ExtendedHeader struct {
	Header

	KeyPhase uint8

	PacketNumberLen uint8
	PacketNumber    int64
}

func (h *ExtendedHeader) parse(b *bytes.Reader, v uint32) (bool /* reserved bits valid */, error) {
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

// ReadUint24 reads a uint24
func ReadUint24(b io.ByteReader) (uint32, error) {
	var b1, b2, b3 uint8
	var err error
	if b3, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b2, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b1, err = b.ReadByte(); err != nil {
		return 0, err
	}
	return uint32(b1) + uint32(b2)<<8 + uint32(b3)<<16, nil
}

// ReadUint16 reads a uint16
func ReadUint16(b io.ByteReader) (uint16, error) {
	var b1, b2 uint8
	var err error
	if b2, err = b.ReadByte(); err != nil {
		return 0, err
	}
	if b1, err = b.ReadByte(); err != nil {
		return 0, err
	}
	return uint16(b1) + uint16(b2)<<8, nil
}
