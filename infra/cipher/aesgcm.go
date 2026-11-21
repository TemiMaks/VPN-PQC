package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"

	"pqc-vpn/domain"
)

const (
	PacketTypeData byte = 0x01
	HeaderSize          = 13
	NonceSize           = 12
	TagSize             = 16
	Overhead            = HeaderSize + TagSize
)

var _ domain.PacketCipher = (*AESGCMCipher)(nil)

type AESGCMCipher struct {
	sessionID   uint32
	sendAEAD    cipher.AEAD
	recvAEAD    cipher.AEAD
	sendCounter atomic.Uint64
	replayMu    sync.Mutex
	replay      ReplayWindow
}

func NewAESGCMCipher(keys domain.SessionKeys) (*AESGCMCipher, error) {
	sendBlock, err := aes.NewCipher(keys.SendKey[:])
	if err != nil {
		return nil, err
	}
	sendAEAD, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, err
	}

	recvBlock, err := aes.NewCipher(keys.RecvKey[:])
	if err != nil {
		return nil, err
	}
	recvAEAD, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, err
	}

	return &AESGCMCipher{
		sessionID: keys.SessionID,
		sendAEAD:  sendAEAD,
		recvAEAD:  recvAEAD,
	}, nil
}

func (c *AESGCMCipher) Seal(plaintext []byte) ([]byte, error) {
	var counter uint64
	for {
		current := c.sendCounter.Load()
		if current == math.MaxUint64 {
			return nil, domain.ErrCounterExhausted
		}
		if c.sendCounter.CompareAndSwap(current, current+1) {
			counter = current
			break
		}
	}

	header := make([]byte, HeaderSize)
	header[0] = PacketTypeData
	binary.BigEndian.PutUint32(header[1:5], c.sessionID)
	binary.BigEndian.PutUint64(header[5:13], counter)

	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	out := make([]byte, HeaderSize, HeaderSize+len(plaintext)+TagSize)
	copy(out, header)
	out = c.sendAEAD.Seal(out, nonce, plaintext, header)
	return out, nil
}

func (c *AESGCMCipher) Open(packet []byte) ([]byte, error) {
	if len(packet) < Overhead {
		return nil, domain.ErrInvalidPacket
	}
	if packet[0] != PacketTypeData {
		return nil, domain.ErrInvalidPacket
	}

	sessionID := binary.BigEndian.Uint32(packet[1:5])
	if sessionID != c.sessionID {
		return nil, domain.ErrSessionMismatch
	}

	counter := binary.BigEndian.Uint64(packet[5:13])
	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	c.replayMu.Lock()
	err := c.replay.Check(counter)
	c.replayMu.Unlock()
	if err != nil {
		return nil, err
	}

	plaintext, err := c.recvAEAD.Open(nil, nonce, packet[HeaderSize:], packet[:HeaderSize])
	if err != nil {
		return nil, domain.ErrAuthFailed
	}

	c.replayMu.Lock()
	replayErr := c.replay.Check(counter)
	if replayErr == nil {
		c.replay.Update(counter)
	}
	c.replayMu.Unlock()
	if replayErr != nil {
		return nil, replayErr
	}

	return plaintext, nil
}
