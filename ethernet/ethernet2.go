package ethernet

import (
	"bytes"

	"github.com/bio-routing/tflow2/convert"
)

const (
	TYPE_ARP = 0x0806
)

type EthernetII struct {
	Destination MACAddr
	Source      MACAddr
	Type        uint16
}

func (e *EthernetII) Serialize(buf *bytes.Buffer) {
	buf.Write(e.Destination[:])
	buf.Write(e.Source[:])
	buf.Write(convert.Uint16Byte(e.Type))
}
