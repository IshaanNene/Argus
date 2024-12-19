package main

import (
	"fmt"
	"log" 
	_"os"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/layers"
	_"github.com/jedib0t/go-pretty/table"
	_"github.com/jedib0t/go-pretty/text"
)

func main() {
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		var srcPort, dstPort uint16
		var seqNum, ackNum uint32
		var windowSize uint16
		var checksum uint16
		var urgentPointer uint16
		var protocol string

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			seqNum = tcp.Seq
			ackNum = tcp.Ack
			windowSize = tcp.Window
			checksum = tcp.Checksum
			urgentPointer = tcp.Urgent
			protocol = "TCP"
			fmt.Println(protocol)
			fmt.Println("+----------------------+----------------------+")
			fmt.Printf("| Source Port          | Destination Port      |\n")
			fmt.Printf("|  %-20d | %-21d |\n", srcPort, dstPort)
			fmt.Println("+----------------------+-----------------------+")
			fmt.Printf("| Sequence Number      |                       |\n")
			fmt.Printf("|         %-20d |                       |\n", seqNum)
			fmt.Println("+----------------------+----------------------")
			fmt.Printf("| Acknowledgment Number |                      |\n")
			fmt.Printf("|         %-20d |                       |\n", ackNum)
			fmt.Println("+----------------------+-------------------+")
			fmt.Printf("| Data Offset | Reserved | Flags | Window Size  |\n")
			fmt.Printf("| %-11d |   0   |   0   |      %-10d |\n", 5, windowSize)
			fmt.Println("+----------------------+--------------------+")
			fmt.Printf("| Checksum          | Urgent Pointer          |\n")
			fmt.Printf("|    %-20d | %-21d |\n", checksum, urgentPointer)
			fmt.Println("+----------------------+-----------------------+")
			fmt.Println("|             Options (if any, variable)         |")
			fmt.Println("+-------------------------------------------------+")
			fmt.Println("|                    Data (variable)            |")
			fmt.Println("+-------------------------------------------------+")
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			length := udp.Length
			checksum := udp.Checksum
			protocol = "UDP"
			fmt.Println(protocol)
			fmt.Println("+----------------------+-----------------------+")
			fmt.Printf("| Source Port          | Destination Port      |\n")
			fmt.Printf("|  %-20d | %-21d |\n", srcPort, dstPort)
			fmt.Println("+----------------------+-----------------------+")
			fmt.Printf("| Length              | Checksum              |\n")
			fmt.Printf("|       %-20d |   %-20d |\n", length, checksum)
			fmt.Println("+----------------------+-----------------------+")
			fmt.Println("|                    Data (variable)            |")
			fmt.Println("+-------------------------------------------------+")
		}
	}
}