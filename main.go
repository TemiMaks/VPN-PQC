package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pqc-vpn/application"
	"pqc-vpn/domain"
	"pqc-vpn/infra/cipher"
	"pqc-vpn/infra/handshake"
	"pqc-vpn/infra/tun"
	"pqc-vpn/infra/udp"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if len(os.Args) > 3 || (len(os.Args) == 3 && os.Args[2] == "") {
			log.Fatal("Użycie: vpn-daemon keygen [NOWY_KATALOG]")
		}
		dir := application.DefaultKeysDir
		if len(os.Args) == 3 {
			dir = os.Args[2]
		}
		if err := handshake.GenerateIdentityFiles(dir); err != nil {
			log.Fatal(err)
		}
		log.Printf("Zapisano klucze Ed25519 w %s. Udostępniaj tylko identity.pub.", dir)
		return
	}

	cfg := application.LoadConfig()
	if cfg.Mode != "client" && cfg.Mode != "server" {
		log.Fatal("Tryb musi być client albo server")
	}
	if cfg.Identity == "" || cfg.PeerKey == "" {
		log.Fatal("Ścieżki -identity i -peer-key nie mogą być puste")
	}

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

	defer dev.Close()
	defer netTransport.Close()
	provider, err := handshake.NewClassicKeyProvider(netTransport, cfg.Mode == "server", cfg.Identity, cfg.PeerKey)
	if err != nil {
		log.Printf("Błąd kluczy tożsamości: %v", err)
		return
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	var keyProvider domain.KeyProvider = provider
	keys, err := keyProvider.GetSessionKeys(handshakeCtx)
	cancel()
	if err != nil {
		log.Printf("Błąd wymiany kluczy: %v", err)
		return
	}
	packetCipher, err := cipher.NewAESGCMCipher(keys)
	if err != nil {
		log.Printf("Błąd szyfrowania: %v", err)
		return
	}
	log.Println("[+] Ustanowiono uwierzytelnioną sesję")
	service := application.NewTunnelService(dev, netTransport, packetCipher)
	service.Run(ctx)

	log.Println("[*] Zamykanie tunelu VPN...")
}
