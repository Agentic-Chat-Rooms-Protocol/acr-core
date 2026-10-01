package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/zeebo/blake3"
)

// Blake3Hash computes the 32-byte BLAKE3 cryptographic hash of data.
func Blake3Hash(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// Blake3Hex computes the hexadecimal string of the BLAKE3 hash of data.
func Blake3Hex(data []byte) string {
	h := blake3.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Compose constructs a canonical, versioned, length-prefixed byte buffer.
// Format:
// header\n
// {len}:{part_0}\n
// {len}:{part_1}\n
// ...
func Compose(header string, parts ...[]byte) []byte {
	var out []byte
	out = append(out, []byte(header)...)
	out = append(out, '\n')
	for _, p := range parts {
		lenStr := strconv.Itoa(len(p))
		out = append(out, []byte(lenStr)...)
		out = append(out, ':')
		out = append(out, p...)
		out = append(out, '\n')
	}
	return out
}

// GenerateKeypair generates a new Ed25519 keypair using crypto/rand.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// Sign signs message using the provided Ed25519 private key.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify verifies a 64-byte Ed25519 signature over msg using pub.
func Verify(pub ed25519.PublicKey, msg []byte, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// SignHex signs message and returns the hexadecimal encoded signature string.
func SignHex(priv ed25519.PrivateKey, msg []byte) string {
	sig := Sign(priv, msg)
	return hex.EncodeToString(sig)
}

// VerifyHex verifies a hex-encoded Ed25519 signature.
func VerifyHex(pubHex string, msg []byte, sigHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	return Verify(pubBytes, msg, sigBytes), nil
}
