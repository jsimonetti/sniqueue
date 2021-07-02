package quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/marten-seemann/qtls-go1-16"
	"golang.org/x/crypto/hkdf"
)

func newAESHeaderProtector(suite *qtls.CipherSuiteTLS13, trafficSecret []byte, isLongHeader bool) *AESHeaderProtector {
	hpKey := hkdfExpandLabel(suite.Hash, trafficSecret, []byte{}, "quic hp", suite.KeyLen)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
	return &AESHeaderProtector{
		block:        block,
		mask:         make([]byte, block.BlockSize()),
		isLongHeader: isLongHeader,
	}
}

type AESHeaderProtector struct {
	mask         []byte
	block        cipher.Block
	isLongHeader bool
}

func (p *AESHeaderProtector) DecryptHeader(sample []byte, firstByte *byte, hdrBytes []byte) {
	p.apply(sample, firstByte, hdrBytes)
}

func (p *AESHeaderProtector) apply(sample []byte, firstByte *byte, hdrBytes []byte) {
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

// NewInitialAEAD creates a new AEAD for Initial encryption / decryption.
func NewInitialAEAD(connID []byte, v uint32) *LongHeaderOpener {
	initialSecret := hkdf.Extract(crypto.SHA256.New, connID, getSalt(v))
	clientSecret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())

	key, iv := computeInitialKeyAndIV(clientSecret)

	decrypter := qtls.AEADAESGCMTLS13(key, iv)

	return newLongHeaderOpener(decrypter, newAESHeaderProtector(initialSuite, clientSecret, true))
}

func newLongHeaderOpener(aead cipher.AEAD, headerProtector *AESHeaderProtector) *LongHeaderOpener {
	return &LongHeaderOpener{
		aead:            aead,
		headerProtector: headerProtector,
		nonceBuf:        make([]byte, aead.NonceSize()),
	}
}

type LongHeaderOpener struct {
	aead            cipher.AEAD
	headerProtector *AESHeaderProtector
	highestRcvdPN   int64 // highest packet number received (which could be successfully unprotected)

	// use a single slice to avoid allocations
	nonceBuf []byte
}

func (o *LongHeaderOpener) Open(dst, src []byte, pn int64, ad []byte) ([]byte, error) {
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

func (o *LongHeaderOpener) DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte) {
	o.headerProtector.DecryptHeader(sample, firstByte, pnBytes)
}

func UnpackHeader(hd *LongHeaderOpener, hdr *Header, data []byte, version uint32) (*ExtendedHeader, error) {
	r := bytes.NewReader(data)

	hdrLen := hdr.ParsedLen
	if int64(len(data)) < hdrLen+4+16 {
		return nil, UnmarshalQUICError
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
	if parseErr != nil && parseErr != UnmarshalQUICBitsError {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != 4 {
		copy(data[extHdr.ParsedLen:hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}
	return extHdr, parseErr
}
