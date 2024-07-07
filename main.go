package main

import (
	"bytes"
	"flag"
	"syscall"

	"github.com/taktv6/gparm/ethernet"
	"github.com/vishvananda/netlink"

	bnet "github.com/bio-routing/bio-rd/net"
	log "github.com/sirupsen/logrus"
)

var (
	ifaName = flag.String("i", "", "Interface to run on")
)

func main() {
	flag.Parse()

	if *ifaName == "" {
		log.Fatal("interface name must be provided (-i parameter)")
	}

	ifa, err := ethernet.NewEthernetInterface(*ifaName, getARPBPF(), syscall.ETH_P_ARP)
	if err != nil {
		log.Errorf("unable to get ethernet interface handle: %v", err)
	}

	for {
		pkt, _, err := ifa.RecvPacket()
		if err != nil {
			log.Errorf("failed to receive packet: %v", err)
			return
		}

		rxb := bytes.NewBuffer(pkt)
		arp, err := UnmarshalARP(rxb)
		if err != nil {
			log.Errorf("failed to unmarshal ARP packet: %v", err)
			continue
		}

		senderIP := bnet.IPv4(arp.SenderIP)
		targetIP := bnet.IPv4(arp.TargetIP)

		log.Infof("ARP: Who has %s? Tell %s!", targetIP.String(), senderIP.String())

		routes, err := netlink.RouteGet(targetIP.ToNetIP())
		if err != nil {
			log.Errorf("unable to get route for %s: %v", targetIP.String(), err)
		}

		if len(routes) == 0 {
			continue
		}

		route := routes[0]
		if uint32(route.LinkIndex) == ifa.GetIfIndex() {
			continue
		}

		log.Infof("route for %s points out another interface than where APR request was received: Performing proxy ARP!", targetIP.String())

		resp := &ARP{
			HardwareType: HWTYPE_ETH,
			ProtocolType: PROTOTYPE_IPV4,
			HardwareSize: HWSIZE_ETH,
			ProtocolSize: PROTOSIZE_IPV4,
			OpCode:       OPCODE_RESPONSE,
			SenderMAC:    ifa.GetMACAddress(),
			SenderIP:     arp.TargetIP,
			TargetMAC:    arp.SenderMAC,
			TargetIP:     arp.SenderIP,
		}

		ethHdr := ethernet.EthernetII{
			Destination: arp.SenderMAC,
			Source:      ifa.GetMACAddress(),
			Type:        ethernet.TYPE_ARP,
		}

		txb := bytes.NewBuffer(nil)
		ethHdr.Serialize(txb)
		resp.Serialize(txb)

		con := ifa.NewConn(arp.SenderMAC)
		respPkt := txb.Bytes()
		_, err = con.Write(respPkt)
		if err != nil {
			log.Errorf("failed to send ARP packet: %v", err)
			continue
		}

		con.Close()
	}
}

/*
takt@tl1 ~ % sudo tcpdump -n -i any arp -dd
[sudo] password for takt:
tcpdump: data link type LINUX_SLL2
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 1, 0x00000806 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
*/

func getARPBPF() *ethernet.BPF {
	b := ethernet.NewBPF()
	b.AddTerm(ethernet.BPFTerm{
		Code: 0x28,
		Jt:   0,
		Jf:   0,
		K:    0x0000000c,
	})
	b.AddTerm(ethernet.BPFTerm{
		Code: 0x15,
		Jt:   0,
		Jf:   1,
		K:    0x00000806,
	})
	b.AddTerm(ethernet.BPFTerm{
		Code: 0x6,
		Jt:   0,
		Jf:   0,
		K:    0x00040000,
	})
	b.AddTerm(ethernet.BPFTerm{
		Code: 0x6,
		Jt:   0,
		Jf:   0,
		K:    0x00000000,
	})

	return b
}
