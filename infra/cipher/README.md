# Cipher Package

## Responsibility

Provides AES-256-GCM packet sealing and opening behind the `domain.PacketCipher` interface. Replay protection is kept separate so authentication completes before replay state is mutated.

## Packet Wire Format

| Byte Offset | Size | Field | Description |
|---|---:|---|---|
| 0 | 1 | Packet Type | Data packet type value `0x01` |
| 1 | 4 | Session ID | Session identifier in network byte order |
| 5 | 8 | Counter | Monotonic packet counter in network byte order |
| 13 | plaintext length | Ciphertext | AES-256-GCM ciphertext |
| 13 + plaintext length | 16 | Authentication Tag | GCM authentication tag |

The fixed header size is 13 bytes. The GCM nonce is 12 bytes: four zero bytes followed by the 8-byte counter in network byte order. The 13-byte header is used as GCM additional authenticated data (AAD). The complete overhead is 29 bytes: 13-byte header plus 16-byte tag.

## Anti-Replay Window

`ReplayWindow` uses a 64-bit sliding window. Counters older than 64 positions behind the highest authenticated counter are rejected. Authentication failure does not mutate replay state.

## Usage

```go
ctx := context.Background()

clientKeys, serverKeys, err := cipher.GenerateTestKeyPair()
if err != nil {
	return err
}

var clientProvider domain.KeyProvider = &cipher.StaticKeyProvider{Keys: clientKeys}
var serverProvider domain.KeyProvider = &cipher.StaticKeyProvider{Keys: serverKeys}

cKeys, err := clientProvider.GetSessionKeys(ctx)
if err != nil {
	return err
}
sKeys, err := serverProvider.GetSessionKeys(ctx)
if err != nil {
	return err
}

client, err := cipher.NewAESGCMCipher(cKeys)
if err != nil {
	return err
}
server, err := cipher.NewAESGCMCipher(sKeys)
if err != nil {
	return err
}

packet, err := client.Seal([]byte("payload"))
if err != nil {
	return err
}
plaintext, err := server.Open(packet)
```

## Running Tests

```sh
go test -v ./infra/cipher/...
```
