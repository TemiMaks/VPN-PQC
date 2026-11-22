package domain

import (
	"context"
	"errors"
)

var (
	ErrInvalidPacket    = errors.New("invalid packet")
	ErrSessionMismatch  = errors.New("session mismatch")
	ErrReplayAttack     = errors.New("replay attack")
	ErrAuthFailed       = errors.New("authentication failed")
	ErrCounterExhausted = errors.New("counter exhausted")
)

type SessionKeys struct {
	SessionID uint32
	SendKey   [32]byte
	RecvKey   [32]byte
}

type KeyProvider interface {
	GetSessionKeys(ctx context.Context) (SessionKeys, error)
}

type PacketCipher interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(packet []byte) ([]byte, error)
}
