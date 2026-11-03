package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	cIFF_TUN   = 0x0001 // Flaga trybu TUN (warstwa IP, bez nagłówków Ethernet)
	cIFF_NO_PI = 0x1000 // Brak 4-bajtowego nagłówka Packet Information ze strony kernela
	cTUNSETIFF = 0x400454ca // Stała ioctl dla TUNSETIFF na architekturze Linux x86_64
	ifnamsiz   = 16
)

// Struktura ifreq zgodna z nagłówkami kernela Linuksa (<linux/if.h>)
type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_pad  [22]byte
}

// TunDevice reprezentuje utworzony wirtualny interfejs sieciowy
type TunDevice struct {
	File *os.File
	Name string
}

// OpenTun tworzy wirtualny interfejs TUN w jądrze
func OpenTun(name string) (*TunDevice, error) {
	// 1. Otwarcie pliku sterownika TUN/TAP
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("błąd otwarcia /dev/net/tun: %w", err)
	}

	var req ifReq
	req.Flags = cIFF_TUN | cIFF_NO_PI
	copy(req.Name[:], []byte(name))

	// 2. Wywołanie ioctl rejestrujące interfejs w systemie
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(cTUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF nie powiódł się: %v", errno)
	}

	// Odczytanie właściwej nazwy przypisanej przez jądro
	actualName := string(req.Name[:])
	for i, b := range req.Name {
		if b == 0 {
			actualName = string(req.Name[:i])
			break
		}
	}

	return &TunDevice{
		File: file,
		Name: actualName,
	}, nil
}

// Configure nadaje adres IP z maską (np. "10.8.0.1/24"), ustawia MTU oraz podnosi interfejs (UP)
func (t *TunDevice) Configure(cidrIP string, mtu int) error {
	// 1. Nadanie adresu IP i maski: ip addr add <cidr> dev <name>
	cmdAddr := exec.Command("ip", "addr", "add", cidrIP, "dev", t.Name)
	if out, err := cmdAddr.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd ustawiania IP (%s): %v, output: %s", cidrIP, err, string(out))
	}

	// 2. Ustawienie MTU: ip link set dev <name> mtu <mtu>
	// Przy VPN z nagłówkiem UDP i PQC, optymalne MTU tunelu to zazwyczaj 1420 bajtów
	cmdMTU := exec.Command("ip", "link", "set", "dev", t.Name, "mtu", fmt.Sprintf("%d", mtu))
	if out, err := cmdMTU.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd ustawiania MTU (%d): %v, output: %s", mtu, err, string(out))
	}

	// 3. Podniesienie interfejsu: ip link set dev <name> up
	cmdUp := exec.Command("ip", "link", "set", "dev", t.Name, "up")
	if out, err := cmdUp.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd podnoszenia interfejsu (UP): %v, output: %s", err, string(out))
	}

	return nil
}

// Close zamyka deskryptor (spowoduje to automatyczne usunięcie interfejsu z Linuksa)
func (t *TunDevice) Close() error {
	if t.File != nil {
		return t.File.Close()
	}
	return nil
}