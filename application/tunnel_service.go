package application

import (
	"context"
	"log"

	"pqc-vpn/domain"
)

type TunnelService struct {
	tun       domain.TunnelDevice
	transport domain.PacketTransport
	cipher    domain.PacketCipher
}

func NewTunnelService(tun domain.TunnelDevice, transport domain.PacketTransport, cipher domain.PacketCipher) *TunnelService {
	return &TunnelService{
		tun:       tun,
		transport: transport,
		cipher:    cipher,
	}
}

func (s *TunnelService) Run(ctx context.Context) {
	// Graceful shutdown: zamknięcie deskryptorów odblokuje wiszące Read/Receive
	go func() {
		<-ctx.Done()
		s.transport.Close()
		s.tun.Close()
	}()

	// Goroutine 1: Sieć (UDP) -> Jądro (TUN)
	go func() {
		buf := make([]byte, BufferSize)
		for {
			n, err := s.transport.Receive(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[NET READ ERR] %v", err)
				continue
			}

			packet, err := s.cipher.Open(buf[:n])
			if err != nil {
				continue
			}
			if _, err := s.tun.Write(packet); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[TUN WRITE ERR] %v", err)
			}
		}
	}()

	// Goroutine 2: Jądro (TUN) -> Sieć (UDP)
	buf := make([]byte, BufferSize)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[TUN READ ERR] %v", err)
			continue
		}

		packet, err := s.cipher.Seal(buf[:n])
		if err != nil {
			log.Printf("[CIPHER SEAL ERR] %v", err)
			return
		}
		if err := s.transport.Send(packet); err != nil {
			if ctx.Err() != nil {
				return
			}
			// Ignorujemy lub logujemy brak klienta przed pierwszym pakietem
			continue
		}
	}
}
