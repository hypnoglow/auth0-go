package authkit

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"gopkg.in/square/go-jose.v2"
)

var (
	testPrivateRSAKey *rsa.PrivateKey
	testPublicRSAKey  *rsa.PublicKey
	testSigner        jose.Signer
)

func init() {
	// prepare private key

	b, err := ioutil.ReadFile("testdata/private.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		panic("failed to decode PEM data")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse RSA key: " + err.Error())
	}

	testPrivateRSAKey = priv
	testPublicRSAKey = &priv.PublicKey

	// prepare signer

	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       testPrivateRSAKey,
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		panic(err)
	}

	testSigner = signer
}
