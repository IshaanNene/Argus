package main

import (
	"fmt"
	"log"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("lo0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
    // for packet := range packetSource.Packets() {
    //     // Network layer
    //     if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
    //         ip, _ := ipLayer.(*layers.IPv4)
    //         fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
    //     }
    
    //     // Transport layer
    //     if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
    //         tcp, _ := tcpLayer.(*layers.TCP)
    //         fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
    //     }
    // }
    
}