package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
	cTUNSETIFF = 0x400454ca
	ifnamsiz   = 16
)

type ifReq struct {
	Name  [ifnamsiz]byte
	Flags uint16
	_pad  [22]byte
}

type TunDevice struct {
	File *os.File
	Name string
}

func OpenTun(name string) (*TunDevice, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("błąd otwarcia /dev/net/tun: %w", err)
	}

	var req ifReq
	req.Flags = cIFF_TUN | cIFF_NO_PI
	copy(req.Name[:], []byte(name))

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

func (t *TunDevice) Configure(cidrIP string, mtu int) error {
	cmdAddr := exec.Command("ip", "addr", "add", cidrIP, "dev", t.Name)
	if out, err := cmdAddr.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd ustawiania IP (%s): %v, output: %s", cidrIP, err, string(out))
	}

	cmdMTU := exec.Command("ip", "link", "set", "dev", t.Name, "mtu", fmt.Sprintf("%d", mtu))
	if out, err := cmdMTU.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd ustawiania MTU (%d): %v, output: %s", mtu, err, string(out))
	}

	cmdUp := exec.Command("ip", "link", "set", "dev", t.Name, "up")
	if out, err := cmdUp.CombinedOutput(); err != nil {
		return fmt.Errorf("błąd podnoszenia interfejsu (UP): %v, output: %s", err, string(out))
	}

	return nil
}

// Implementacja interfejsu domain.TunnelDevice:

func (t *TunDevice) Read(p []byte) (int, error)  { return t.File.Read(p) }
func (t *TunDevice) Write(p []byte) (int, error) { return t.File.Write(p) }
func (t *TunDevice) InterfaceName() string       { return t.Name }

func (t *TunDevice) Close() error {
	if t.File != nil {
		return t.File.Close()
	}
	return nil
}