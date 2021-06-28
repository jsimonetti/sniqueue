package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
var debug bool
var loadList listFlags

func init() {
	flag.IntVar(&queueNumber, "queue", 100, "queue number to listen on")
	flag.IntVar(&markNumber, "mark", 1, "mark matched packets")
	flag.BoolVar(&dropPackets, "drop", false, "drop matched packets (has precedence over mark)")
	flag.BoolVar(&debug, "debug", false, "additional logging")
	flag.Var(&loadList, "list", "list of domains to load (use multiple times to load more files)")
}

var list tree.Tree
var logger *log.Logger

func main() {
	flag.Parse()
	logger = log.Default()

	verdict := "drop"
	if !dropPackets {
		verdict = fmt.Sprintf("mark %d", markNumber)
	}
	if debug {
		logger.SetPrefix("[DEBUG] ")
	}
	logger.Printf("Starting on queue %d with verdict %s", queueNumber, verdict)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer func() {
		signal.Stop(c)
		cancel()
	}()

	list = tree.New()
	for _, file := range loadList {
		logger.Printf("loading domains from %s", file)
		list.LoadFile(file)
	}
	logger.Printf("domain list contains %d entries", list.Size())

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(queueNumber),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}
	if debug {
		config.Logger = logger
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		logger.Fatalln("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	fn := func(a nfqueue.Attribute) int {
		p := &PacketInfo{
			Queue:   nf,
			ID:      *a.PacketID,
			Payload: *a.Payload,
		}
		if debug {
			size := ""
			if a.CapLen != nil {
				size = fmt.Sprintf(" (len: %d)", *a.CapLen)
			}
			mark := ""
			if a.Mark != nil {
				size = fmt.Sprintf(" (mark: %d)", *a.Mark)
			}
			logger.Printf("received packet%s%s", size, mark)
		}
		handle(p)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.Register(ctx, fn)
	if err != nil {
		logger.Fatalln(err)
		return
	}

	select {
	case <-c:
		cancel()
		logger.Print("receive signal, closing:")
	case <-ctx.Done():
		logger.Print("context done, closing")
	}
}

func handle(p *PacketInfo) {
	pkt, err := parse.Parse(p.Payload)
	if err != nil {
		p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)
	}

	if list.Match(pkt.DomainName()) {
		if dropPackets {
			if debug {
				logger.Print("Dropped packet")
			}
			p.Queue.SetVerdict(p.ID, nfqueue.NfDrop)
			return
		}

		if debug {
			logger.Printf("Marked packet with %d", markNumber)
		}
		p.Queue.SetVerdictWithMark(p.ID, nfqueue.NfAccept, markNumber)
		return
	}

	if debug {
		logger.Print("Accepted packet")
	}
	p.Queue.SetVerdict(p.ID, nfqueue.NfAccept)

}

type listFlags []string

func (i *listFlags) String() string {
	return ""
}

func (i *listFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
