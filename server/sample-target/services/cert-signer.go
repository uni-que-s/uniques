// Package pki mints internal service certificates for mTLS.
package pki

import "crypto/rsa"

// MintServiceCert generates a 2048-bit RSA signing key — quantum-vulnerable.
func MintServiceCert() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(nil, 2048)
}
