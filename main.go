package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/Lochnair/go-patricia/patricia"
	"github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/shomali11/util/xstrings"
)

type PacketInfo struct {
	Queue           *nfqueue.Nfqueue
	ID              uint32
	IPVersion       int
	IPHeaderLength  int
	Length          uint16
	Protocol        int
	Source          net.IP
	Destination     net.IP
	SourcePort      uint16
	DestinationPort uint16
	Data            []byte
	Cursor          int
}

func main() {
	initDomainList(list)
	initNfTables()

	// Send every 3rd packet in a flow with destination port 443 to nfqueue queue 100
	// # sudo iptables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:3 -j NFQUEUE --queue-num 100 --queue-bypass
	// # sudo ip6tables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:3 -j NFQUEUE --queue-num 100 --queue-bypass
	// # sudo nft insert rule ip filter FORWARD tcp dport 443 ct original packets 3 counter queue num 100 bypass

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

	ctx, cancel := context.WithTimeout(context.Background(), 86400*time.Second)
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
	p.Destination = p.Data[16:20]
	p.Protocol = int(p.Data[9])
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

	p.Cursor = p.IPHeaderLength * 4

	if p.Protocol == 6 {
		handleTCP(p)
		return
	}
	if p.Protocol == 17 {
		handleUDP(p)
		return
	}

	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleIPV6(p *PacketInfo) {
	p.Source = p.Data[8:24]
	p.Destination = p.Data[24:40]
	p.Protocol = int(p.Data[6])
	p.Length = binary.BigEndian.Uint16(p.Data[4:6])

	// We need to get the offset to parse the content
	p.Cursor = p.Cursor + 40 // Fix THIS?

	if p.Protocol == 6 {
		handleTCP(p)
		return
	}
	if p.Protocol == 17 {
		handleUDP(p)
		return
	}

	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleTCP(p *PacketInfo) {
	// add code to skip SYN, SYN/ACK, RST, etc

	p.SourcePort = binary.BigEndian.Uint16(p.Data[p.Cursor+0 : p.Cursor+2])
	p.DestinationPort = binary.BigEndian.Uint16(p.Data[p.Cursor+2 : p.Cursor+4])

	dataOffset := int(p.Data[p.Cursor+12] >> 4)

	if dataOffset < 5 {
		// Invalid TCP data offset
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	p.Cursor = p.Cursor + int(dataOffset)*4
	if p.Cursor >= len(p.Data) {
		// TCP data offset greater than packet length
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	// Only handle TLS
	if p.Data[p.Cursor] == 0x16 {
		handleTLS(p)
		return
	}

	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleUDP(p *PacketInfo) {
	// Just print out the id and payload of the nfqueue packet
	fmt.Printf("UDP%d [%d]\t%v\n", p.IPVersion, p.ID, p.Data)
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func handleTLS(p *PacketInfo) {
	payload := p.Data[p.Cursor:]

	handshakeProtocol := payload[5]

	// Only attempt to match on client hellos
	if handshakeProtocol != 0x01 {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
		return
	}

	handshakeLength := binary.BigEndian.Uint16(payload[3:5]) + 5
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

			switch verdict(domainName) {
			case nfqueue.NfDrop:
				p.Queue.SetVerdict(p.ID, nfqueue.NfDrop)
				addblocklist(p.IPVersion, p.Destination)
			default:
				p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
			}
			return
		}

		extensionOffset += extensionLen
	}
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
}

func verdict(domainName string) int {

	reversedDomain := xstrings.Reverse(domainName)
	_, _, found, leftover := domainTrie.FindSubtree(patricia.Prefix(reversedDomain))

	/*
	 * Match is true if either the domain matches perfectly in the Trie
	 * or if the first character of the leftover is a wildcard
	 */
	match := found || (len(leftover) > 0 && leftover[0] == 42)
	if match {
		return nfqueue.NfDrop
		fmt.Printf("dropping %s\n", domainName)
	}
	return nfqueue.NfAccept
}

var list = []string{
	"dns.google",
	"dns64.dns.google",
	"dns.google.com",
	"google-public-dns-a.google.com",
	"google-public-dns-b.google.com",
}

var domainTrie *patricia.Trie

func initDomainList(list []string) {
	domainTrie = patricia.NewTrie()
	for _, domain := range list {
		reversedDomain := xstrings.Reverse(domain)
		domainTrie.Insert(patricia.Prefix(reversedDomain), 0)
	}
}

func initNfTables() error {
	conn = &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if t.Name == tableName {
			table = t
		}
	}
	setv4, err = conn.GetSetByName(table, blocklistV4)
	if err != nil {
		return err
	}
	setv6, err = conn.GetSetByName(table, blocklistV6)
	if err != nil {
		return err
	}
	return nil
}

const (
	tableName   string = "filter"
	blocklistV4 string = "blocklist_v4"
	blocklistV6 string = "blocklist_v6"
)

var conn *nftables.Conn
var setv4 *nftables.Set
var setv6 *nftables.Set
var table *nftables.Table

func addblocklist(v int, dst net.IP) {
	if v == 4 {
		conn.SetAddElements(setv4, []nftables.SetElement{{
			Key: dst,
		}})
		return
	}
	if v == 6 {
		conn.SetAddElements(setv6, []nftables.SetElement{{
			Key: dst,
		}})
	}
}
