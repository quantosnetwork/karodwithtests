package packets

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"log"
	"time"
)

// we are using eth0 as interface, var Iface will be parametrized later mac would be en0
var Iface = "en0"
var pcapSnapLen = 16 << 10
var bpfFilter = "tcp"

type Envelope struct {
	bytes         int64
	bidirectional *bidirectionalStream // twin
	done          bool
}

type bidirectionalStream struct {
	key            StreamKey
	a, b           *Envelope
	lastPacketSeen time.Time
}

// StreamKey is used to link bidirectional streams to each other
type StreamKey struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k StreamKey) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// timeout is the length of time to wait befor flushing connections and
// bidirectional stream pairs.
const timeout time.Duration = time.Minute * 5

// StreamFactory implements tcpassmebly.StreamFactory
type StreamFactory struct {
	bMap map[StreamKey]*bidirectionalStream
}

func (f *StreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	s := &Envelope{}
	k := StreamKey{netFlow, tcpFlow}
	bd := f.bMap[k]
	if bd == nil {
		bd = &bidirectionalStream{a: s, key: k}
		log.Printf("[%v] created first side of bidirectional stream", bd.key)
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.bMap[StreamKey{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		log.Printf("[%v] found second side of bidirectional stream", bd.key)
		bd.b = s
		// Clear out the bidi we're using from the map, just in case.
		delete(f.bMap, k)
	}
	s.bidirectional = bd
	return s
}

// emptyStream is used to finish bidirectionalStream that only have one stream, in
// collectOldStreams.
var emptyStream = &Envelope{done: true}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout', and sets/finishes the 'b' stream inside them.  The 'a' stream may
// still receive packets after this.
func (f *StreamFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, bd := range f.bMap {
		if bd.lastPacketSeen.Before(cutoff) {
			log.Printf("[%v] timing out old stream", bd.key)
			bd.b = emptyStream // stub out b with an empty stream.
			delete(f.bMap, k)  // remove it from our map.
			bd.maybeFinish()   // if b was the last stream we were waiting for, finish up.
		}
	}
}

func (e *Envelope) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
		e.bytes += int64(len(r.Bytes))
		if r.Skip > 0 {
			e.bytes += int64(r.Skip)
		}
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from a file and could be very old.
		if e.bidirectional.lastPacketSeen.Before(r.Seen) {
			e.bidirectional.lastPacketSeen = r.Seen
		}
	}
}

func (e *Envelope) ReassemblyComplete() {
	e.done = true
	e.bidirectional.maybeFinish()
}

// maybeFinish will wait until both directions are complete, then print out
// stats.
func (bd *bidirectionalStream) maybeFinish() {
	switch {
	case bd.a == nil:
		log.Fatalf("[%v] a should always be non-nil, since it's set when bidis are created", bd.key)
	case !bd.a.done:
		log.Printf("[%v] still waiting on first stream", bd.key)
	case bd.b == nil:
		log.Printf("[%v] no second stream yet", bd.key)
	case !bd.b.done:
		log.Printf("[%v] still waiting on second stream", bd.key)
	default:
		log.Printf("[%v] FINISHED, bytes: %d tx, %d rx", bd.key, bd.a.bytes, bd.b.bytes)
	}
}

func InitBidirectionalStream() {
	handle, err := pcap.OpenLive(Iface, int32(pcapSnapLen), true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		panic(err)
	}

	streamFactory := &StreamFactory{bMap: make(map[StreamKey]*bidirectionalStream)}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.MaxBufferedPagesTotal = 100000
	assembler.MaxBufferedPagesPerConnection = 1000

	log.Println("reading in packets")

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(timeout / 4)
	for {
		select {
		case packet := <-packets:

			log.Println(packet)

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past minute.
			log.Println("---- FLUSHING ----")
			assembler.FlushOlderThan(time.Now().Add(-timeout))
			streamFactory.collectOldStreams()
		}
	}
}
