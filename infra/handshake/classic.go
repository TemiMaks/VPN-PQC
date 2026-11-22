package handshake

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
	"pqc-vpn/domain"
)

const (
	clientHello byte = 0x02 + iota
	serverHello
	clientFinish
	serverFinish
)

// ClassicKeyProvider establishes fresh, authenticated session keys over UDP.
type ClassicKeyProvider struct {
	Transport domain.PacketTransport
	Server    bool
	Identity  ed25519.PrivateKey
	Peer      ed25519.PublicKey
}

var _ domain.KeyProvider = (*ClassicKeyProvider)(nil)

func (p *ClassicKeyProvider) GetSessionKeys(ctx context.Context) (keys domain.SessionKeys, err error) {
	if ctx.Err() != nil {
		return keys, ctx.Err()
	}
	if len(p.Identity) != ed25519.PrivateKeySize || len(p.Peer) != ed25519.PublicKeySize {
		return keys, domain.ErrAuthFailed
	}
	// Receive blocks; closing the transport interrupts a cancelled exchange.
	stop := context.AfterFunc(ctx, func() { _ = p.Transport.Close() })
	defer func() {
		stop()
		if ctx.Err() != nil {
			keys, err = domain.SessionKeys{}, ctx.Err()
		}
	}()

	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return keys, err
	}
	public := private.PublicKey().Bytes()
	var remote, response []byte
	if p.Server {
		remote, err = p.receive(clientHello, 32)
	} else {
		if err = p.send(clientHello, public); err != nil {
			return keys, err
		}
		response, err = p.receive(serverHello, 32+ed25519.SignatureSize)
		if err == nil {
			remote = response[:32]
		}
	}
	if err != nil {
		return keys, err
	}
	remotePublic, err := ecdh.X25519().NewPublicKey(remote)
	if err != nil {
		return keys, err
	}
	secret, err := private.ECDH(remotePublic)
	if err != nil {
		return keys, err
	}

	// Both peers build the same transcript, in client/server order.
	ownIdentity := p.Identity.Public().(ed25519.PublicKey)
	transcript := []byte("pqc-vpn/classic/v1")
	if p.Server {
		transcript = append(transcript, remote...)
		transcript = append(transcript, public...)
		transcript = append(transcript, p.Peer...)
		transcript = append(transcript, ownIdentity...)
	} else {
		transcript = append(transcript, public...)
		transcript = append(transcript, remote...)
		transcript = append(transcript, ownIdentity...)
		transcript = append(transcript, p.Peer...)
	}
	var material [100]byte // two traffic keys, session ID and a confirmation key
	if _, err = io.ReadFull(hkdf.New(sha256.New, secret, nil, transcript), material[:]); err != nil {
		return keys, err
	}
	keys.SessionID = binary.BigEndian.Uint32(material[64:68])
	copy(keys.SendKey[:], material[:32])
	copy(keys.RecvKey[:], material[32:64])
	if p.Server {
		keys.SendKey, keys.RecvKey = keys.RecvKey, keys.SendKey
	}

	clientSignature := signedContext("client", transcript)
	serverSignature := signedContext("server", transcript)
	clientProof := confirmation(material[68:], "client", transcript)
	serverProof := confirmation(material[68:], "server", transcript)
	if p.Server {
		if err = p.send(serverHello, append(public, ed25519.Sign(p.Identity, serverSignature)...)); err != nil {
			return domain.SessionKeys{}, err
		}
		finish, err := p.receive(clientFinish, ed25519.SignatureSize+sha256.Size)
		if err != nil {
			return domain.SessionKeys{}, err
		}
		if !ed25519.Verify(p.Peer, clientSignature, finish[:ed25519.SignatureSize]) || !hmac.Equal(clientProof, finish[ed25519.SignatureSize:]) {
			return domain.SessionKeys{}, domain.ErrAuthFailed
		}
		if err := p.send(serverFinish, serverProof); err != nil {
			return domain.SessionKeys{}, err
		}
	} else {
		if !ed25519.Verify(p.Peer, serverSignature, response[32:]) {
			return domain.SessionKeys{}, domain.ErrAuthFailed
		}
		if err = p.send(clientFinish, append(ed25519.Sign(p.Identity, clientSignature), clientProof...)); err != nil {
			return domain.SessionKeys{}, err
		}
		finish, err := p.receive(serverFinish, sha256.Size)
		if err != nil {
			return domain.SessionKeys{}, err
		}
		if !hmac.Equal(serverProof, finish) {
			return domain.SessionKeys{}, domain.ErrAuthFailed
		}
	}
	return keys, nil
}

func (p *ClassicKeyProvider) send(kind byte, data []byte) error {
	return p.Transport.Send(append([]byte{kind}, data...))
}

func (p *ClassicKeyProvider) receive(kind byte, size int) ([]byte, error) {
	buf := make([]byte, size+2)
	n, err := p.Transport.Receive(buf)
	if err != nil {
		return nil, err
	}
	if n != size+1 || buf[0] != kind {
		return nil, domain.ErrInvalidPacket
	}
	return buf[1:n], nil
}

func signedContext(role string, transcript []byte) []byte {
	return append([]byte(role+"/signature/"), transcript...)
}

func confirmation(key []byte, role string, transcript []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(role + "/confirmation/"))
	mac.Write(transcript)
	return mac.Sum(nil)
}
