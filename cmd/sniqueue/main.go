package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/jsimonetti/sniqueue/internal/parse"
	"github.com/jsimonetti/sniqueue/internal/tree"

	"github.com/florianl/go-nfqueue"
)

type PacketInfo struct {
	Queue   *nfqueue.Nfqueue
	ID      uint32
	Payload []byte
}

var queueNumber int
var markNumber int
var dropPackets bool

func init() {
	flag.IntVar(&queueNumber, "queue", 100, "queue number to listen on")
	flag.IntVar(&markNumber, "mark", 123, "mark matched packets")
	flag.BoolVar(&dropPackets, "drop", false, "drop matched packets")
}

func main() {
	flag.Parse()

	list = tree.New()
	// Send every 3rd packet in a flow with destination port 443 to nfqueue queue 100
	// # sudo iptables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:20 -j NFQUEUE --queue-num 100 --queue-bypass
	// # sudo ip6tables -I FORWARD -p tcp --dport 443 -m connbytes --connbytes-mode packets --connbytes-dir original --connbytes 3:20 -j NFQUEUE --queue-num 100 --queue-bypass
	// # sudo nft insert rule ip filter FORWARD tcp dport 443 ct original packets 3-20 counter queue num 100 bypass

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(queueNumber),
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
			Queue:   nf,
			ID:      *a.PacketID,
			Payload: *a.Payload,
		}
		go handle(p)
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

var list tree.Tree

func handle(p *PacketInfo) {
	pkt, err := parse.Parse(p.Payload)
	if err != nil {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
	}

	if list.Match(pkt.DomainName()) {
		if dropPackets {
			fmt.Print("Dropped packet\n")
			p.Queue.SetVerdict(p.ID, nfqueue.NfDrop)
			return
		}
		fmt.Print("Marked packet\n")
		p.Queue.SetVerdictWithMark(p.ID, nfqueue.NfAccept, markNumber)
	} else {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
	}
}
