package handshake

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"pqc-vpn/domain"
)

// GenerateIdentityFiles writes an Ed25519 identity as PEM files in a new directory.
func GenerateIdentityFiles(dir string) error {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("nie można utworzyć nowego katalogu kluczy %q: %w", dir, err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := os.WriteFile(filepath.Join(dir, "identity.key"), privatePEM, 0600); err != nil {
		return err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return os.WriteFile(filepath.Join(dir, "identity.pub"), publicPEM, 0644)
}

// NewClassicKeyProvider loads a private identity and a previously trusted peer key.
func NewClassicKeyProvider(transport domain.PacketTransport, server bool, identityPath, peerPath string) (*ClassicKeyProvider, error) {
	privateDER, err := readPEM(identityPath)
	if err != nil {
		return nil, err
	}
	private, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, err
	}
	publicDER, err := readPEM(peerPath)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, err
	}
	identity, identityOK := private.(ed25519.PrivateKey)
	peer, peerOK := public.(ed25519.PublicKey)
	if !identityOK || !peerOK {
		return nil, fmt.Errorf("wymagane klucze Ed25519")
	}
	return &ClassicKeyProvider{Transport: transport, Server: server, Identity: identity, Peer: peer}, nil
}

func readPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("niepoprawny plik PEM: %s", path)
	}
	return block.Bytes, nil
}
