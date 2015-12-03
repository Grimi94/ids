package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap

import (
    "bufio"
    "io"
    "net/http"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/tcpassembly"
    "github.com/google/gopacket/tcpassembly/tcpreader"
    "log"
)

var (
    pcapFile string = "malware.pcap"
    handle   *pcap.Handle
    err      error
)

type httpStreamFactory struct{}

type httpStream struct {
    net, transport gopacket.Flow
    r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
    hstream := &httpStream{
        net:       net,
        transport: transport,
        r:         tcpreader.NewReaderStream(),
    }
    go hstream.run() // Important... we must guarantee that data from the reader stream is read.

    // ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
    return &hstream.r
}

func (h *httpStream) run() {
    buf := bufio.NewReader(&h.r)
    for {
        req, err := http.ReadRequest(buf)
        if err == io.EOF {
            // We must read until we see an EOF... very important!
            return
        } else if err != nil {
            //log.Println("Error reading stream", h.net, h.transport, ":", err,"\n")
        } else {
            bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
            req.Body.Close()
            log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body \n")
        }

    }
}

func main() {
    // Open file instead of device
    handle, err = pcap.OpenOffline(pcapFile)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Loop through packets in file and assemble them
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    streamFactory := &httpStreamFactory{}
    streamPool := tcpassembly.NewStreamPool(streamFactory)
    assembler := tcpassembly.NewAssembler(streamPool)

    for packet := range packetSource.Packets() {
        if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
            //log.Println("Unusable packet")
            continue
        }
        tcp := packet.TransportLayer().(*layers.TCP)
        assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
    }
}
