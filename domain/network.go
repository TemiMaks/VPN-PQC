package domain

import "io"

// TunnelDevice reprezentuje lokalny wirtualny interfejs (np. Linux TUN)
type TunnelDevice interface {
	io.ReadWriteCloser
	InterfaceName() string
}

// PacketTransport reprezentuje warstwę transportową przesyłającą ramki w sieć (np. UDP)
type PacketTransport interface {
	Send(payload []byte) error
	Receive(buf []byte) (int, error)
	Close() error
}