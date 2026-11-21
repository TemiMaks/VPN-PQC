# Cipher Package

## Responsibility

Provides ChaCha20-Poly1305 packet sealing and opening behind the `domain.PacketCipher` interface. Replay protection is kept separate so AEAD authentication completes before replay state mutates.

## Packet Wire Format

| Byte Offset | Size | Field | Description |
|---|---:|---|---|
| 0 | 1 | Packet Type | Data packet type value `0x01` |
| 1 | 4 | Session ID | Session identifier in network byte order |
| 5 | 8 | Counter | Monotonic packet counter in network byte order |
| 13 | plaintext length | Ciphertext | ChaCha20-Poly1305 ciphertext |
| 13 + plaintext length | 16 | Authentication Tag | Poly1305 authentication tag |

The fixed header size is 13 bytes. The complete overhead is 29 bytes: 13-byte header plus 16-byte tag.

## Usage

Placeholder for cipher construction and `Seal`/`Open` usage after implementation.

## Running Tests

```sh
go test -v ./infra/cipher/...
```
