package ethernet

type EthernetInterfaceFactoryI interface {
	New(name string, bpf *BPF, protocol uint16) (EthernetInterfaceI, error)
}

type EthernetInterfaceFactory struct{}

func NewEthernetInterfaceFactory() *EthernetInterfaceFactory {
	return &EthernetInterfaceFactory{}
}

func (eif *EthernetInterfaceFactory) New(name string, bpf *BPF, protocol uint16) (EthernetInterfaceI, error) {
	return NewEthernetInterface(name, bpf, protocol)
}

type MockEthernetInterfaceFactory struct{}

func NewMockEthernetInterfaceFactory() *MockEthernetInterfaceFactory {
	return &MockEthernetInterfaceFactory{}
}

func (meif *MockEthernetInterfaceFactory) New(name string, bpf *BPF) (EthernetInterfaceI, error) {
	return NewMockEthernetInterface(), nil
}
