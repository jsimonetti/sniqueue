package quic

import (
	"crypto"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"

	"github.com/jsimonetti/sniqueue/internal/qtls"
	"golang.org/x/crypto/hkdf"
)

var UnmarshalQUICError = errors.New("insufficient bytes to unmarshal QUIC")
var unmarshalQUICDecryptError = errors.New("cannot decrypt QUIC payload")
var UnmarshalNoQUICError = errors.New("not a QUIC packet")
var UnmarshalNoQUICInitialError = errors.New("not an initial QUIC packet")
var UnmarshalQUICBitsError = errors.New("unknown bits in QUIC header")
var UnmarshalQUICUnsupportedVersion = errors.New("unsupported QUIC version")

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
	quicSaltOld      = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt22       = []byte{0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a}
	quicSalt23       = []byte{0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02}
	quicSaltDraft34  = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltDraftQ50 = []byte{0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3, 0xA7, 0xF0, 0xD3, 0xB5, 0x6B, 0x45}
)

func getSalt(v uint32) []byte {
	if v == VersionDraft34 || v == Version1 {
		return quicSaltDraft34
	}
	if v == VersionQ50 {
		return quicSaltDraftQ50
	}
	if v == VersionDraft22 {
		return quicSalt22
	}
	if v == VersionDraft27 {
		return quicSalt23
	}
	return quicSaltOld
}

// The version numbers, making grepping easier
const (
	VersionDraft22 uint32 = 0xfaceb001
	VersionDraft27 uint32 = 0xfaceb002
	VersionDraft29 uint32 = 0xff00001d
	VersionDraft32 uint32 = 0xff000020
	VersionDraft34 uint32 = 0xff000022
	VersionQ50     uint32 = 0x51303530
	Version1       uint32 = 0x1
)

// SupportedVersions lists the versions that the server supports
// must be in sorted descending order
var SupportedVersions = []uint32{Version1, VersionDraft34, VersionDraft32, VersionDraft27, VersionDraft22, VersionDraft29, VersionQ50}

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
