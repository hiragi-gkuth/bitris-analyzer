package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("please specify dump file.")
		return
	}
	filepath := os.Args[1]

	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Read in packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sessions := classifySessions(packetSource)

	for session, packets := range sessions {
		payloadLen := getSSHPayloadSizeForSession(packets)
		fmt.Printf("%s,%d\n", session, payloadLen)
	}
}

func classifySessions(packetSource *gopacket.PacketSource) tcpSessions {
	sessions := make(tcpSessions)
	for p := range packetSource.Packets() {
		tcpLayer := p.Layer(layers.LayerTypeTCP)
		ipLayer := p.Layer(layers.LayerTypeIPv4)
		if tcpLayer != nil && ipLayer != nil {
			t, _ := tcpLayer.(*layers.TCP)
			i, _ := ipLayer.(*layers.IPv4)
			session := &tcpSession{
				t:       t,
				dstHost: i.DstIP.String(),
				srcHost: i.SrcIP.String(),
			}
			sessions[session.Key(22)] = append(sessions[session.Key(22)], p)
		}
	}
	return sessions
}

func getSSHPayloadSizeForSession(packets []gopacket.Packet) int {
	size := 0
	for _, p := range packets {
		appLayer := p.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		size += len(appLayer.Payload())
	}
	return size
}

type tcpSession struct {
	t       *layers.TCP
	dstHost string
	srcHost string
}

type tcpSessions map[string][]gopacket.Packet

func (rcv tcpSession) Key(servePort int) string {
	portSum := int(rcv.t.SrcPort+rcv.t.DstPort) - servePort
	clientHost := ""
	if int(rcv.t.SrcPort) == servePort {
		clientHost = rcv.dstHost
	} else {
		clientHost = rcv.srcHost
	}

	return fmt.Sprintf("%s:%d", clientHost, portSum)
}
