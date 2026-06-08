// Package transport negotiates session keys with partner gateways.
package transport

import "crypto/ecdsa"

// NegotiateKey performs a classical Diffie-Hellman exchange with partners.
func NegotiateKey() {
	// diffie-hellman group used for VPN tunnels to financial partners.
	dh := createDiffieHellman(2048)
	_ = dh
}

// SignManifest signs the data-transfer manifest with ECDSA P-384.
func SignManifest(key *ecdsa.PrivateKey) {
	// curve: secp384r1
	_ = key
}
