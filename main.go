package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"pqc-vpn/application"
	"pqc-vpn/domain"
	"pqc-vpn/infra/tun"
	"pqc-vpn/infra/udp"
)

func main() {
	cfg := application.LoadConfig()

	// 1. Inicjalizacja interfejsu TUN (infra)
	dev, err := tun.OpenTun(cfg.TunName)
	if err != nil {
		log.Fatalf("Błąd otwarcia TUN: %v", err)
	}
	if err := dev.Configure(cfg.TunCIDR, cfg.MTU); err != nil {
		dev.Close()
		log.Fatalf("Błąd konfiguracji interfejsu: %v", err)
	}
	log.Printf("[+] Interfejs %s gotowy i podniesiony z adresem %s!", dev.InterfaceName(), cfg.TunCIDR)

	// 2. Inicjalizacja transportu sieciowego (infra)
	var netTransport domain.PacketTransport
	if cfg.Mode == "server" {
		netTransport, err = udp.NewServerTransport(cfg.ListenPort)
		if err == nil {
			log.Printf("[*] Serwer VPN nasłuchuje na UDP port %d", cfg.ListenPort)
		}
	} else {
		netTransport, err = udp.NewClientTransport(cfg.ServerAddr)
		if err == nil {
			log.Printf("[*] Klient VPN połączony z %s", cfg.ServerAddr)
		}
	}
	if err != nil {
		dev.Close()
		log.Fatalf("Błąd inicjalizacji transportu: %v", err)
	}

	// 3. Uruchomienie serwisu aplikacji z obsługą SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	service := application.NewTunnelService(dev, netTransport)
	service.Run(ctx)

	log.Println("[*] Zamykanie tunelu VPN...")
}