package application

import (
	"flag"
	"path/filepath"
)

const (
	BufferSize     = 2048
	DefaultMTU     = 1420
	DefaultKeysDir = "keys"
)

type Config struct {
	Mode       string
	ListenPort int
	ServerAddr string
	TunName    string
	TunCIDR    string
	MTU        int
	Identity   string
	PeerKey    string
}

func LoadConfig() *Config {
	cfg := &Config{
		MTU: DefaultMTU,
	}

	flag.StringVar(&cfg.Mode, "mode", "server", "Tryb pracy: 'server' lub 'client'")
	flag.IntVar(&cfg.ListenPort, "port", 9999, "Port UDP dla serwera")
	flag.StringVar(&cfg.ServerAddr, "server", "127.0.0.1:9999", "Adres serwera (dla trybu client)")
	flag.StringVar(&cfg.TunName, "tun", "tun0", "Nazwa interfejsu TUN")
	flag.StringVar(&cfg.TunCIDR, "cidr", "", "Adres CIDR interfejsu TUN (opcjonalnie)")
	flag.StringVar(&cfg.Identity, "identity", filepath.Join(DefaultKeysDir, "identity.key"), "Prywatny klucz Ed25519 (PEM)")
	flag.StringVar(&cfg.PeerKey, "peer-key", filepath.Join(DefaultKeysDir, "peer.pub"), "Zaufany publiczny klucz rozmówcy (PEM)")
	flag.Parse()

	if cfg.TunCIDR == "" {
		if cfg.Mode == "server" {
			cfg.TunCIDR = "10.8.0.1/24"
		} else {
			cfg.TunCIDR = "10.8.0.2/24"
		}
	}

	return cfg
}
