package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"sync"
	"pqc-vpn/tun"
)

const bufferSize = 2048

func main() {
	mode := flag.String("mode", "server", "Tryb pracy: 'server' lub 'client'")
	listenPort := flag.Int("port", 9999, "Port UDP dla serwera")
	serverAddrStr := flag.String("server", "127.0.0.1:9999", "Adres serwera (dla trybu client)")
	tunName := flag.String("tun", "tun0", "Nazwa interfejsu TUN")
	flag.Parse()

	// 1. Utworzenie wirtualnego interfejsu TUN
	dev, err := tun.OpenTun(*tunName)
	if err != nil {
		log.Fatalf("Błąd otwarcia TUN: %v", err)
	}
	defer dev.Close()

	// 2. Konfiguracja adresu IP w zależności od trybu
	var tunCIDR string
	if *mode == "server" {
		tunCIDR = "10.8.0.1/24"
	} else {
		tunCIDR = "10.8.0.2/24"
	}

	err = dev.Configure(tunCIDR, 1420)
	if err != nil {
		log.Fatalf("Błąd konfiguracji interfejsu: %v", err)
	}

	log.Printf("[+] Interfejs %s gotowy i podniesiony z adresem %s!", dev.Name, tunCIDR)

	// 3. Uruchomienie pętli sieciowej
	if *mode == "server" {
		runServer(dev.File, *listenPort)
	} else {
		runClient(dev.File, *serverAddrStr)
	}
}

func runServer(tunFile *os.File, port int) {
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Błąd bindowania socketu UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("[*] Serwer VPN nasłuchuje na UDP port %d", port)

	var mu sync.RWMutex
	var lastClientAddr *net.UDPAddr

	// Goroutine 1: Pakiety z sieci UDP -> do jądra Linuksa (TUN)
	go func() {
		buf := make([]byte, bufferSize)
		for {
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("[SERVER UDP READ ERR] %v", err)
				continue
			}

			mu.Lock()
			lastClientAddr = remoteAddr
			mu.Unlock()

			_, err = tunFile.Write(buf[:n])
			if err != nil {
				log.Printf("[SERVER TUN WRITE ERR] %v", err)
			}
		}
	}()

	// Goroutine 2: Pakiety wygenerowane w systemie (TUN) -> do klienta (UDP)
	go func() {
		buf := make([]byte, bufferSize)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				log.Printf("[SERVER TUN READ ERR] %v", err)
				continue
			}

			mu.RLock()
			client := lastClientAddr
			mu.RUnlock()

			if client == nil {
				log.Printf("[SERVER DROP] Przeczytano %d B z TUN, ale nie znam adresu klienta!", n)
				continue
			}

			_, err = conn.WriteToUDP(buf[:n], client)
			if err != nil {
				log.Printf("[SERVER UDP WRITE ERR] %v", err)
			}
		}
	}()

	waitForSigterm()
}

func runClient(tunFile *os.File, serverAddrStr string) {
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrStr)
	if err != nil {
		log.Fatalf("Niepoprawny adres serwera: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatalf("Błąd połączenia UDP z serwerem: %v", err)
	}
	defer conn.Close()

	log.Printf("[*] Klient VPN połączony z %s", serverAddr.String())

	// Goroutine 1: Odczyt z TUN -> wysyłka przez UDP do serwera
	go func() {
		buf := make([]byte, bufferSize)
		for {
			n, err := tunFile.Read(buf)
			if err != nil {
				continue
			}
			_, _ = conn.Write(buf[:n])
		}
	}()

	// Goroutine 2: Odbiór z UDP (odpowiedzi od serwera) -> wstrzyknięcie do TUN
	go func() {
		buf := make([]byte, bufferSize)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				continue
			}
			_, _ = tunFile.Write(buf[:n])
		}
	}()

	// Blokada wątku głównego: program czeka na Ctrl+C, trzymając otwarty tun0
	waitForSigterm()
}

func waitForSigterm() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("\n[*] Zamykanie tunelu VPN...")
}