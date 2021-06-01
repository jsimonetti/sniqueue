package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
)

type IPProtocol uint8

const (
	// IPProtocolIPv4 IPProtocol = 4
	IPProtocolTCP IPProtocol = 6
	IPProtocolUDP IPProtocol = 17
	// IPProtocolIPv6 IPProtocol = 41
)

type Port uint16

func (a Port) String() string {
	return strconv.Itoa(int(a))
}

type PacketInfo struct {
	Queue           *nfqueue.Nfqueue
	ID              uint32
	IPVersion       int
	IPHeaderLength  int
	Length          uint16
	Protocol        IPProtocol
	Source          net.IP
	Destination     net.IP
	SourcePort      Port
	DestinationPort Port
	Data            []byte
	Offset          int
}

func main() {
	// Send every 3rd packet in a flow with destination port 443 to nfqueue queue 100
	// # sudo iptables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:3 -j NFQUEUE --queue-num 100 --queue-bypass
	// # sudo ip6tables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:3 -j NFQUEUE --queue-num 100 --queue-bypass

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      100,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()

	fn := func(a nfqueue.Attribute) int {
		p := &PacketInfo{
			Queue: nf,
			ID:    *a.PacketID,
			Data:  *a.Payload,
		}
		handle(p)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.Register(ctx, fn)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}

func handle(p *PacketInfo) {
	p.IPVersion = int(p.Data[0]) >> 4
	p.IPHeaderLength = int(p.Data[0]) & 0x0F
	switch p.IPVersion {
	case 4: // IPv4
		handleIPV4(p)
	case 6: // IPv6
		handleIPV6(p)
	default:
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
	}
}

func handleIPV4(p *PacketInfo) {
	p.Source = p.Data[12:16]
	p.Source = p.Data[12:16]
	p.Destination = p.Data[16:20]
	p.Protocol = IPProtocol(p.Data[9])
	p.Length = binary.BigEndian.Uint16(p.Data[2:4])

	// This code is added for the following enviroment:
	// * Windows 10 with TSO option activated. ( tested on Hyper-V, RealTek ethernet driver )
	if p.Length == 0 {
		// If using TSO(TCP Segmentation Offload), length is zero.
		// The actual packet length is the length of data.
		p.Length = uint16(len(p.Data))
	}

	if p.Length < 20 {
		// Invalid (too small) IP length
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	} else if p.IPHeaderLength < 5 {
		// Invalid (too small) IP header length
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	} else if int(p.IPHeaderLength*4) > int(p.Length) {
		// Invalid IP header length > IP length
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	p.Offset = p.IPHeaderLength * 4

	if p.Protocol == IPProtocolTCP {
		handleTCP(p)
		return
	}
	if p.Protocol == IPProtocolUDP {
		handleUDP(p)
		return
	}

	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleIPV6(p *PacketInfo) {
	p.Source = p.Data[8:24]
	p.Destination = p.Data[24:40]
	p.Protocol = IPProtocol(p.Data[6])
	p.Length = binary.BigEndian.Uint16(p.Data[4:6])

	// We need to get the offset to parse the content
	p.Offset = p.Offset + 40 // Fix THIS?

	if p.Protocol == IPProtocolTCP {
		handleTCP(p)
		return
	}
	if p.Protocol == IPProtocolUDP {
		handleUDP(p)
		return
	}

	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleTCP(p *PacketInfo) {
	// add code to skip SYN, SYN/ACK, RST, etc

	p.SourcePort = Port(binary.BigEndian.Uint16(p.Data[p.Offset+0 : p.Offset+2]))
	p.DestinationPort = Port(binary.BigEndian.Uint16(p.Data[p.Offset+2 : p.Offset+4]))

	dataOffset := int(p.Data[p.Offset+12] >> 4)

	if dataOffset < 5 {
		// Invalid TCP data offset
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	p.Offset = p.Offset + int(dataOffset)*4
	if p.Offset >= len(p.Data) {
		// TCP data offset greater than packet length
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Only handle TLS
	if p.Data[p.Offset] == 0x16 {
		handleTLS(p)
		return
	}

	fmt.Printf("TCP%d non-TLS [%d] %s:%s->%s:%s\t%v\n", p.IPVersion, p.ID, p.Source, p.SourcePort, p.Destination, p.DestinationPort, p.Data[p.Offset:])
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleUDP(p *PacketInfo) {
	// Just print out the id and payload of the nfqueue packet
	fmt.Printf("UDP%d [%d]\t%v\n", p.IPVersion, p.ID, p.Data)
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleTLS(p *PacketInfo) {
	payload := p.Data[p.Offset:]

	handshakeLength := binary.BigEndian.Uint16(payload[3:5]) + 5
	handshakeProtocol := payload[5]

	// Only attempt to match on client hellos
	if handshakeProtocol != 0x01 {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	payloadLength := uint16(len(payload))
	// If we don't have all the data, try matching with what we have
	if handshakeLength > payloadLength {
		handshakeLength = payloadLength
	}

	offset, baseOffset, extensionOffset := uint16(0), uint16(43), uint16(2)

	if baseOffset+2 > uint16(len(payload)) {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Get the length of the session ID
	sessionIdLength := uint16(payload[baseOffset])

	if (sessionIdLength + baseOffset + 2) > handshakeLength {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Get the length of the ciphers
	cipherLenStart := baseOffset + sessionIdLength + 1
	cipherLen := binary.BigEndian.Uint16(payload[cipherLenStart : cipherLenStart+2])
	offset = baseOffset + sessionIdLength + cipherLen + 2

	if offset > handshakeLength {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Get the length of the compression methods list
	compressionLen := uint16(payload[offset+1])
	offset += compressionLen + 2

	if offset > handshakeLength {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Get the length of the extensions
	extensionsLen := binary.BigEndian.Uint16(payload[offset : offset+2])

	// Add the full offset to were the extensions start
	extensionOffset += offset

	if extensionsLen > handshakeLength {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	for extensionOffset < extensionsLen+offset {
		extensionId := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])

		extensionOffset += 2

		extensionLen := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
		extensionOffset += 2

		if extensionId == 0 {
			// We don't need the server name list length or name_type, so skip that
			extensionOffset += 3

			// Get the length of the domain name
			nameLength := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
			extensionOffset += 2

			domainName := string(payload[extensionOffset : extensionOffset+nameLength])
			fmt.Printf("TLS Domainname (v%d) [%d] %s:%s->%s:%s\t%s\n", p.IPVersion, p.ID, p.Source, p.SourcePort, p.Destination, p.DestinationPort, domainName)
			p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
			return
		}

		extensionOffset += extensionLen
	}
	fmt.Printf("TCP%d no dnsname found [%d] %s:%s->%s:%s\t%#v\n", p.IPVersion, p.ID, p.Source, p.SourcePort, p.Destination, p.DestinationPort, p.Data[p.Offset:])
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}
