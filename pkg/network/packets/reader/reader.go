package reader

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"net/http"
)

type tcpStreamFactory struct{}

type PacketReader struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	buf            *bufio.Reader
	fn             cmdFn
}

func (r *PacketReader) Reassembled(reassemblies []tcpassembly.Reassembly) {
	//TODO implement me
	panic("implement me")
}

func (r *PacketReader) ReassemblyComplete() {
	//TODO implement me
	panic("implement me")
}

func (r *PacketReader) NewReader(net, transport gopacket.Flow) tcpassembly.Stream {
	pStream := &PacketReader{
		net:       net,
		transport: transport,
		buf:       bufio.NewReader(&r.r),
		r:         tcpreader.NewReaderStream(),
	}

	go pStream.run()

	return &pStream.r
}

func (r *PacketReader) run() {
	for {
		req, err := http.ReadRequest(r.buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", r.net, r.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", r.net, r.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

type handler struct{}

type cmdFn = func(cmd uint8, h *handler)
