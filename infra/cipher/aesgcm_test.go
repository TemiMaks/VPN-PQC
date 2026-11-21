package cipher

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"pqc-vpn/domain"
)

func newTestCipherPair(t *testing.T) (*AESGCMCipher, *AESGCMCipher) {
	t.Helper()
	clientKeys, serverKeys, err := GenerateTestKeyPair()
	if err != nil {
		t.Fatalf("GenerateTestKeyPair() error = %v", err)
	}

	clientProvider := &StaticKeyProvider{Keys: clientKeys}
	serverProvider := &StaticKeyProvider{Keys: serverKeys}

	clientConfigured, err := clientProvider.GetSessionKeys(context.Background())
	if err != nil {
		t.Fatalf("client GetSessionKeys() error = %v", err)
	}
	serverConfigured, err := serverProvider.GetSessionKeys(context.Background())
	if err != nil {
		t.Fatalf("server GetSessionKeys() error = %v", err)
	}

	client, err := NewAESGCMCipher(clientConfigured)
	if err != nil {
		t.Fatalf("NewAESGCMCipher(client) error = %v", err)
	}
	server, err := NewAESGCMCipher(serverConfigured)
	if err != nil {
		t.Fatalf("NewAESGCMCipher(server) error = %v", err)
	}
	return client, server
}

func TestBidirectionalRoundTrip(t *testing.T) {
	client, server := newTestCipherPair(t)
	payloads := [][]byte{nil, make([]byte, 1420)}

	for _, payload := range payloads {
		packet, err := client.Seal(payload)
		if err != nil {
			t.Fatalf("client Seal() error = %v", err)
		}
		plain, err := server.Open(packet)
		if err != nil {
			t.Fatalf("server Open() error = %v", err)
		}
		if len(payload) != len(plain) {
			t.Fatalf("client to server payload length = %d, want %d", len(plain), len(payload))
		}

		packet, err = server.Seal(payload)
		if err != nil {
			t.Fatalf("server Seal() error = %v", err)
		}
		plain, err = client.Open(packet)
		if err != nil {
			t.Fatalf("client Open() error = %v", err)
		}
		if len(plain) != len(payload) {
			t.Fatalf("server to client payload length = %d, want %d", len(plain), len(payload))
		}
	}
}

func TestMalformedPackets(t *testing.T) {
	client, server := newTestCipherPair(t)

	truncated := make([]byte, Overhead-1)
	if _, err := server.Open(truncated); !errors.Is(err, domain.ErrInvalidPacket) {
		t.Fatalf("truncated Open() error = %v, want ErrInvalidPacket", err)
	}

	packet, err := client.Seal([]byte("packet"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	wrongType := append([]byte(nil), packet...)
	wrongType[0] ^= 0x01
	if _, err := server.Open(wrongType); !errors.Is(err, domain.ErrInvalidPacket) {
		t.Fatalf("wrong type Open() error = %v, want ErrInvalidPacket", err)
	}

	wrongSession := append([]byte(nil), packet...)
	wrongSession[1] ^= 0x01
	if _, err := server.Open(wrongSession); !errors.Is(err, domain.ErrSessionMismatch) {
		t.Fatalf("wrong session Open() error = %v, want ErrSessionMismatch", err)
	}
}

func flipByte(packet []byte, index int) []byte {
	copyPacket := append([]byte(nil), packet...)
	copyPacket[index] ^= 0x01
	return copyPacket
}

func TestTamperingDoesNotAdvanceReplay(t *testing.T) {
	tamperTests := []struct {
		name  string
		index int
	}{
		{name: "type", index: 0},
		{name: "session id", index: 1},
		{name: "counter", index: 5},
		{name: "ciphertext", index: HeaderSize},
		{name: "tag", index: Overhead - 1},
	}

	for _, tt := range tamperTests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := newTestCipherPair(t)
			packet, err := client.Seal([]byte("legitimate"))
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}

			if tt.name == "tag" {
				tt.index = len(packet) - 1
			}
			tampered := flipByte(packet, tt.index)
			if _, err := server.Open(tampered); err == nil {
				t.Fatalf("tampered packet accepted")
			}

			if _, err := server.Open(packet); err != nil {
				t.Fatalf("legitimate packet after tampering error = %v", err)
			}

			next, err := client.Seal([]byte("next"))
			if err != nil {
				t.Fatalf("next Seal() error = %v", err)
			}
			if _, err := server.Open(next); err != nil {
				t.Fatalf("next legitimate packet error = %v", err)
			}
		})
	}
}

func TestReplayProtection(t *testing.T) {
	client, server := newTestCipherPair(t)

	packet0, err := client.Seal([]byte("counter zero"))
	if err != nil {
		t.Fatalf("Seal(counter zero) error = %v", err)
	}
	if _, err := server.Open(packet0); err != nil {
		t.Fatalf("Open(counter zero) error = %v", err)
	}
	if _, err := server.Open(packet0); !errors.Is(err, domain.ErrReplayAttack) {
		t.Fatalf("duplicate counter zero error = %v, want ErrReplayAttack", err)
	}

	outOfOrderClient, outOfOrderServer := newTestCipherPair(t)
	packet1, _ := outOfOrderClient.Seal([]byte("one"))
	packet2, _ := outOfOrderClient.Seal([]byte("two"))
	packet3, _ := outOfOrderClient.Seal([]byte("three"))
	for _, packet := range [][]byte{packet3, packet1, packet2} {
		if _, err := outOfOrderServer.Open(packet); err != nil {
			t.Fatalf("out-of-order Open() error = %v", err)
		}
	}
	if _, err := outOfOrderServer.Open(packet1); !errors.Is(err, domain.ErrReplayAttack) {
		t.Fatalf("duplicate out-of-order packet error = %v, want ErrReplayAttack", err)
	}

	olderClient, olderServer := newTestCipherPair(t)
	olderClient.sendCounter.Store(65)
	newPacket, err := olderClient.Seal([]byte("jump"))
	if err != nil {
		t.Fatalf("Seal(jump) error = %v", err)
	}
	if _, err := olderServer.Open(newPacket); err != nil {
		t.Fatalf("Open(jump) error = %v", err)
	}
	olderClient.sendCounter.Store(0)
	oldPacket, err := olderClient.Seal([]byte("old"))
	if err != nil {
		t.Fatalf("Seal(old) error = %v", err)
	}
	if _, err := olderServer.Open(oldPacket); !errors.Is(err, domain.ErrReplayAttack) {
		t.Fatalf("packet older than 64 error = %v, want ErrReplayAttack", err)
	}

	jumpClient, jumpServer := newTestCipherPair(t)
	jumpClient.sendCounter.Store(64)
	jumpPacket, err := jumpClient.Seal([]byte("jump 64"))
	if err != nil {
		t.Fatalf("Seal(jump 64) error = %v", err)
	}
	if _, err := jumpServer.Open(jumpPacket); err != nil {
		t.Fatalf("Open(jump 64) error = %v", err)
	}
	if _, err := jumpServer.Open(jumpPacket); !errors.Is(err, domain.ErrReplayAttack) {
		t.Fatalf("duplicate jump packet error = %v, want ErrReplayAttack", err)
	}
}

func TestCounterExhaustion(t *testing.T) {
	client, server := newTestCipherPair(t)
	client.sendCounter.Store(math.MaxUint64 - 1)

	packet, err := client.Seal([]byte("last"))
	if err != nil {
		t.Fatalf("last Seal() error = %v", err)
	}
	if _, err := server.Open(packet); err != nil {
		t.Fatalf("Open(last counter) error = %v", err)
	}

	if _, err := client.Seal([]byte("exhausted")); !errors.Is(err, domain.ErrCounterExhausted) {
		t.Fatalf("exhausted Seal() error = %v, want ErrCounterExhausted", err)
	}
}

func TestConcurrentSealAndOpen(t *testing.T) {
	client, server := newTestCipherPair(t)

	const count = 64
	packets := make([][]byte, count)
	errCh := make(chan error, count)
	var sealWG sync.WaitGroup
	for i := 0; i < count; i++ {
		sealWG.Add(1)
		go func(index int) {
			defer sealWG.Done()
			packet, err := client.Seal([]byte{byte(index)})
			if err == nil {
				packets[index] = packet
			}
			errCh <- err
		}(i)
	}
	sealWG.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Seal() error = %v", err)
		}
	}

	var openWG sync.WaitGroup
	openErrs := make(chan error, count)
	for i := 0; i < count; i++ {
		openWG.Add(1)
		go func(index int) {
			defer openWG.Done()
			_, err := server.Open(packets[index])
			openErrs <- err
		}(i)
	}
	openWG.Wait()
	close(openErrs)
	for err := range openErrs {
		if err != nil {
			t.Fatalf("concurrent Open() error = %v", err)
		}
	}
}
