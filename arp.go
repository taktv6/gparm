package main

import (
	"bytes"
	"fmt"

	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
	"github.com/taktv6/gparm/ethernet"
)

const (
	ETH_HEADER_LEN  = 14
	HWTYPE_ETH      = 1
	HWSIZE_ETH      = 6
	PROTOTYPE_IPV4  = 0x800
	PROTOSIZE_IPV4  = 4
	OPCODE_REQUEST  = 1
	OPCODE_RESPONSE = 2
)

type ARP struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareSize uint8
	ProtocolSize uint8
	OpCode       uint16
	SenderMAC    ethernet.MACAddr
	SenderIP     uint32
	TargetMAC    ethernet.MACAddr
	TargetIP     uint32
}

func UnmarshalARP(buf *bytes.Buffer) (*ARP, error) {
	pdu := &ARP{}
	ethHeader := [ETH_HEADER_LEN]byte{}
	fields := []interface{}{
		&ethHeader,
		&pdu.HardwareType,
		&pdu.HardwareSize,
		&pdu.ProtocolType,
		&pdu.ProtocolSize,
		&pdu.OpCode,
		&pdu.SenderMAC,
		&pdu.SenderIP,
		&pdu.TargetMAC,
		&pdu.TargetIP,
	}

	err := decode.Decode(buf, fields)
	if err != nil {
		return nil, fmt.Errorf("unable to decode fields: %v", err)
	}

	return pdu, nil
}

func (a *ARP) Serialize(buf *bytes.Buffer) {
	buf.Write(convert.Uint16Byte(a.HardwareType))
	buf.Write(convert.Uint16Byte(a.ProtocolType))
	buf.WriteByte(a.HardwareSize)
	buf.WriteByte(a.ProtocolSize)
	buf.Write(convert.Uint16Byte(a.OpCode))
	buf.Write(a.SenderMAC[:])
	buf.Write(convert.Uint32Byte(a.SenderIP))
	buf.Write(a.TargetMAC[:])
	buf.Write(convert.Uint32Byte(a.TargetIP))
}
