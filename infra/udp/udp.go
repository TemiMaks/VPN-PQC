package udp

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

type UDPTransport struct {
	conn           *net.UDPConn
	isServer       bool
	mu             sync.RWMutex
	lastClientAddr *net.UDPAddr
}

func NewServerTransport(port int) (*UDPTransport, error) {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, fmt.Errorf("błąd bindowania socketu UDP: %w", err)
	}
	return &UDPTransport{
		conn:     conn,
		isServer: true,
	}, nil
}

func NewClientTransport(serverAddrStr string) (*UDPTransport, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		return nil, fmt.Errorf("niepoprawny adres serwera: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("błąd połączenia UDP z serwerem: %w", err)
	}
	return &UDPTransport{
		conn:     conn,
		isServer: false,
	}, nil
}

func (u *UDPTransport) Receive(buf []byte) (int, error) {
	if !u.isServer {
		return u.conn.Read(buf)
	}

	n, remoteAddr, err := u.conn.ReadFromUDP(buf)
	if err == nil && remoteAddr != nil {
		u.mu.Lock()
		u.lastClientAddr = remoteAddr
		u.mu.Unlock()
	}
	return n, err
}

func (u *UDPTransport) Send(payload []byte) error {
	if !u.isServer {
		_, err := u.conn.Write(payload)
		return err
	}

	u.mu.RLock()
	client := u.lastClientAddr
	u.mu.RUnlock()

	if client == nil {
		return errors.New("brak znanego adresu klienta")
	}

	_, err := u.conn.WriteToUDP(payload, client)
	return err
}

func (u *UDPTransport) Close() error {
	return u.conn.Close()
}