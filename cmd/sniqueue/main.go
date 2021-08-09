package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/jsimonetti/sniqueue/internal/pcap"

	"github.com/jsimonetti/sniqueue/internal/parse"
	"github.com/jsimonetti/sniqueue/internal/parse/tls"
	"github.com/jsimonetti/sniqueue/internal/tree"

	"github.com/florianl/go-nfqueue"
)

var queueNumber int
var markBadNumber int
var markGoodNumber int
var dropPackets bool
var debug bool
var blog bool
var debugwrite bool
var loadList listFlags

func init() {
	flag.IntVar(&queueNumber, "queue", 100, "queue number to listen on")
	flag.IntVar(&markBadNumber, "mark", 1, "mark matched packets")
	flag.BoolVar(&dropPackets, "drop", false, "drop matched packets (has precedence over mark)")
	flag.BoolVar(&debug, "debug", false, "additional logging")
	flag.BoolVar(&debugwrite, "debugwrite", false, "write unknown packets to pcap file")
	flag.BoolVar(&blog, "log", false, "log all SNI actions")
	flag.Var(&loadList, "list", "list of domains to load (use multiple times to load more files)")
}

var list tree.Tree
var logger *log.Logger

var pcapV4 *pcap.Writer
var pcapV6 *pcap.Writer

func main() {
	flag.Parse()
	markGoodNumber = markBadNumber + 1

	// Assume we are running under systemd or similar and don't print time/date
	// in the logs.
	logger = log.New(os.Stderr, "", 0)

	if debug {
		logger.SetPrefix("[DEBUG] ")
		if debugwrite {
			v4, err := os.Create("/tmp/sniqueue.ipv4.pcap")
			if err != nil {
				logger.Fatalln(err)
			}
			defer v4.Close()
			v6, err := os.Create("/tmp/sniqueue.ipv6.pcap")
			if err != nil {
				logger.Fatalln(err)
			}
			defer v6.Close()
			pcapV4 = pcap.NewWriter(v4)
			pcapV4.WriteFileHeader(pcap.LinkTypeIPv4)
			pcapV6 = pcap.NewWriter(v6)
			pcapV6.WriteFileHeader(pcap.LinkTypeIPv6)
		}
	}

	verdict := "drop"
	if !dropPackets {
		verdict = fmt.Sprintf("mark %d (known bad) %d (known good)", markBadNumber, markGoodNumber)
	}
	logger.Printf("Starting on queue %d with verdict '%s'", queueNumber, verdict)

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
		logger.Printf("loading domains from '%s'", file)
		if err := list.LoadFile(file); err != nil {
			logger.Fatalf("error loading file '%s': %s", file, err)
		}
	}
	logger.Printf("domain list contains %d entries", list.Size())

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(queueNumber),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  30 * time.Second,
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
		handle(nf, *a.Payload, *a.PacketID)
		return 0
	}

	// Register function to listen on nflqueue queue 100
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

func handle(queue *nfqueue.Nfqueue, payload []byte, id uint32) {
	pkt, err := parse.Parse(payload)
	if err != nil {
		if debug {
			logger.Printf("Parse error: %s", err)
			if err != tls.UnmarshalNoTLSError && err != tls.UnmarshalNoTLSHandshakeError {
				if debugwrite {
					if pkt.Version() == 4 {
						pcapV4.WritePacket(payload)
					} else if pkt.Version() == 6 {
						pcapV6.WritePacket(payload)
					}
				}
				if !debugwrite {
					logger.Printf("Packet payload: %#v", payload)
				}
			}
		}
		_ = queue.SetVerdict(id, nfqueue.NfAccept)
		return
	}

	if list.Match(pkt.DomainName()) {
		if dropPackets {
			if debug || blog {
				logger.Printf("Dropped packet (sni: '%s')", pkt.DomainName())
			}
			_ = queue.SetVerdict(id, nfqueue.NfDrop)
			return
		}

		if debug || blog {
			logger.Printf("Marked packet with %d (sni: '%s')", markBadNumber, pkt.DomainName())
		}
		_ = queue.SetVerdictWithMark(id, nfqueue.NfAccept, markBadNumber)
		return
	}

	if debug || blog {
		logger.Printf("Accepted packet (sni: '%s')", pkt.DomainName())
	}
	if dropPackets {
		_ = queue.SetVerdict(id, nfqueue.NfAccept)
		return
	}
	_ = queue.SetVerdictWithMark(id, nfqueue.NfAccept, markGoodNumber)
}

type listFlags []string

func (i *listFlags) String() string {
	return ""
}

func (i *listFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
