package ethernet

import (
	"fmt"
	"net"
	"syscall"

	bnet "github.com/bio-routing/bio-rd/net"
)

const (
	ethALen         = 6
	ethPAll         = 0x0300
	maxMTU          = 9216
	maxLLCLen       = 0x5ff
	ethertypeExtLLC = 0x8870
)

// MACAddr represens a MAC address
type MACAddr [ethALen]byte

func (m MACAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

type EthernetInterface struct {
	rxSocket   int
	devName    string
	ifIndex    uint32
	protocol   uint16
	macAddress MACAddr
}

type EthernetInterfaceI interface {
	RecvPacket() (pkt []byte, src MACAddr, err error)
	SendPacket(dst MACAddr, pkt []byte) error
	Close()
}

func NewEthernetInterface(devName string, bpf *BPF, protocol uint16) (*EthernetInterface, error) {
	ifa, err := net.InterfaceByName(devName)
	if err != nil {
		return nil, fmt.Errorf("net.InterfaceByName failed: %w", err)
	}

	h := &EthernetInterface{
		devName:  devName,
		ifIndex:  uint32(ifa.Index),
		protocol: protocol,
	}

	copy(h.macAddress[:], ifa.HardwareAddr)

	err = h.init(bpf)
	if err != nil {
		return nil, fmt.Errorf("init failed: %w", err)
	}

	return h, nil
}

func (e *EthernetInterface) init(b *BPF) error {
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("socket() failed: %v", err)
	}
	e.rxSocket = socket

	err = e.loadBPF(b)
	if err != nil {
		return fmt.Errorf("unable to load BPF: %w", err)
	}

	err = syscall.Bind(e.rxSocket, &syscall.SockaddrLinklayer{
		Protocol: ethPAll,
		Ifindex:  int(e.ifIndex),
	})
	if err != nil {
		return fmt.Errorf("bind failed: %w", err)
	}

	return nil
}

// Close closes the handler
func (e *EthernetInterface) Close() {
	syscall.Close(e.rxSocket)
}

func (e *EthernetInterface) GetMACAddress() MACAddr {
	return e.macAddress
}

func (e *EthernetInterface) GetIfIndex() uint32 {
	return e.ifIndex
}

func (e *EthernetInterface) RecvPacket() (pkt []byte, src MACAddr, err error) {
	buf := make([]byte, maxMTU)
	nBytes, from, err := syscall.Recvfrom(e.rxSocket, buf, 0)
	if err != nil {
		return nil, MACAddr{}, fmt.Errorf("recvfrom failed: %v", err)
	}

	ll := from.(*syscall.SockaddrLinklayer)
	copy(src[:], ll.Addr[:ethALen])

	return buf[:nBytes], src, nil
}

// SendPacket sends an 802.3 ethernet packet (LLC)
func (e *EthernetInterface) SendPacket(dst MACAddr, pkt []byte) error {
	err := syscall.Sendto(e.rxSocket, pkt, 0, e.getSockaddrLinklayer(dst, e.protocol))
	if err != nil {
		return fmt.Errorf("sendto failed: %v", err)
	}

	return nil
}

func (e *EthernetInterface) getSockaddrLinklayer(dst MACAddr, protocol uint16) *syscall.SockaddrLinklayer {
	sall := &syscall.SockaddrLinklayer{
		Protocol: bnet.Htons(protocol),
		Ifindex:  int(e.ifIndex),
		Hatype:   bnet.Htons(syscall.ARPHRD_ETHER),
		Pkttype:  syscall.PACKET_OTHERHOST,
		Halen:    ethALen,
	}

	for i := uint8(0); i < sall.Halen; i++ {
		sall.Addr[i] = dst[i]
	}

	return sall
}
