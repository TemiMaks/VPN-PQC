package cipher

import (
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
	"pqc-vpn/domain"
)

const (
	PacketTypeData byte = 0x01
	HeaderSize          = 13
	NonceSize           = 12
	Overhead            = 29
)

var _ domain.PacketCipher = (*ChaCha20Poly1305Cipher)(nil)
var _ = chacha20poly1305.KeySize

type ChaCha20Poly1305Cipher struct{}

func NewChaCha20Poly1305Cipher(keys domain.SessionKeys) (*ChaCha20Poly1305Cipher, error) {
	return &ChaCha20Poly1305Cipher{}, nil
}

func (c *ChaCha20Poly1305Cipher) Seal(plaintext []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (c *ChaCha20Poly1305Cipher) Open(packet []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
