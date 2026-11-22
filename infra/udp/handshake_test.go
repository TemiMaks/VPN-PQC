package udp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"pqc-vpn/domain"
	"pqc-vpn/infra/cipher"
	"pqc-vpn/infra/handshake"
)

func TestClassicExchange(t *testing.T) {
	root := t.TempDir()
	clientDir := filepath.Join(root, "client")
	serverDir := filepath.Join(root, "server")
	for _, dir := range []string{clientDir, serverDir} {
		if err := handshake.GenerateIdentityFiles(dir); err != nil {
			t.Fatal(err)
		}
	}
	clientPublic := filepath.Join(clientDir, "identity.pub")
	serverPublic := filepath.Join(serverDir, "identity.pub")

	exchange := func(t *testing.T, trustedServer string) (domain.SessionKeys, domain.SessionKeys, error, error, *UDPTransport, *UDPTransport) {
		t.Helper()
		server, err := NewServerTransport(0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { server.Close() })
		port := server.conn.LocalAddr().(*net.UDPAddr).Port
		client, err := NewClientTransport(fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		clientProvider, err := handshake.NewClassicKeyProvider(client, false, filepath.Join(clientDir, "identity.key"), trustedServer)
		if err != nil {
			t.Fatal(err)
		}
		serverProvider, err := handshake.NewClassicKeyProvider(server, true, filepath.Join(serverDir, "identity.key"), clientPublic)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		type result struct {
			keys domain.SessionKeys
			err  error
		}
		serverResult := make(chan result, 1)
		go func() {
			keys, err := serverProvider.GetSessionKeys(ctx)
			serverResult <- result{keys, err}
		}()
		clientKeys, clientErr := clientProvider.GetSessionKeys(ctx)
		if clientErr != nil {
			cancel()
		}
		s := <-serverResult
		return clientKeys, s.keys, clientErr, s.err, client, server
	}

	t.Run("matching keys and AES-GCM", func(t *testing.T) {
		c, s, clientErr, serverErr, client, server := exchange(t, serverPublic)
		if clientErr != nil || serverErr != nil {
			t.Fatalf("client: %v, server: %v", clientErr, serverErr)
		}
		if c.SessionID != s.SessionID || c.SendKey != s.RecvKey || c.RecvKey != s.SendKey || c.SendKey == c.RecvKey {
			t.Fatal("incorrect directional session keys")
		}
		clientCipher, err := cipher.NewAESGCMCipher(c)
		if err != nil {
			t.Fatal(err)
		}
		serverCipher, err := cipher.NewAESGCMCipher(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, direction := range []struct {
			sender, receiver *UDPTransport
			seal, open       domain.PacketCipher
		}{{client, server, clientCipher, serverCipher}, {server, client, serverCipher, clientCipher}} {
			message := []byte("test packet")
			sealed, err := direction.seal.Seal(message)
			if err != nil {
				t.Fatal(err)
			}
			if err := direction.sender.Send(sealed); err != nil {
				t.Fatal(err)
			}
			if err := direction.receiver.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2048)
			n, err := direction.receiver.Receive(buf)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := direction.open.Open(buf[:n])
			if err != nil || !bytes.Equal(opened, message) {
				t.Fatalf("packet not recovered: %v", err)
			}
		}
		fresh, _, clientErr, serverErr, _, _ := exchange(t, serverPublic)
		if clientErr != nil || serverErr != nil || fresh.SendKey == c.SendKey || fresh.RecvKey == c.RecvKey {
			t.Fatal("second session did not establish fresh traffic keys")
		}
	})

	t.Run("untrusted identity", func(t *testing.T) {
		c, s, clientErr, serverErr, _, _ := exchange(t, clientPublic)
		if !errors.Is(clientErr, domain.ErrAuthFailed) || serverErr == nil || c != (domain.SessionKeys{}) || s != (domain.SessionKeys{}) {
			t.Fatal("untrusted identity produced a session")
		}
	})
}
