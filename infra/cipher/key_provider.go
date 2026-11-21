package cipher

import (
	"context"
	"crypto/rand"
	"encoding/binary"

	"pqc-vpn/domain"
)

// StaticKeyProvider returns configured session keys for tests or static deployments.
type StaticKeyProvider struct {
	Keys domain.SessionKeys
}

func (p *StaticKeyProvider) GetSessionKeys(ctx context.Context) (domain.SessionKeys, error) {
	if err := ctx.Err(); err != nil {
		return domain.SessionKeys{}, err
	}
	return p.Keys, nil
}

// GenerateTestKeyPair returns matching client and server keys.
func GenerateTestKeyPair() (clientKeys domain.SessionKeys, serverKeys domain.SessionKeys, err error) {
	var sessionIDBytes [4]byte
	if _, err := rand.Read(sessionIDBytes[:]); err != nil {
		return clientKeys, serverKeys, err
	}

	var clientSendKey [32]byte
	var clientRecvKey [32]byte
	if _, err := rand.Read(clientSendKey[:]); err != nil {
		return clientKeys, serverKeys, err
	}
	if _, err := rand.Read(clientRecvKey[:]); err != nil {
		return clientKeys, serverKeys, err
	}

	sessionID := binary.BigEndian.Uint32(sessionIDBytes[:])
	clientKeys = domain.SessionKeys{
		SessionID: sessionID,
		SendKey:   clientSendKey,
		RecvKey:   clientRecvKey,
	}
	serverKeys = domain.SessionKeys{
		SessionID: sessionID,
		SendKey:   clientRecvKey,
		RecvKey:   clientSendKey,
	}

	return clientKeys, serverKeys, nil
}
