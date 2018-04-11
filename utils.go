package authkit

import (
	"errors"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func header(token *jwt.JSONWebToken) (jose.Header, error) {
	if len(token.Headers) < 1 {
		return jose.Header{}, errors.New("no headers in the token")
	}

	return token.Headers[0], nil
}

func validateHeaderAlgo(header jose.Header, algo jose.SignatureAlgorithm) error {
	if header.Algorithm != string(algo) {
		return errors.New("invalid algorithm")
	}

	return nil
}

func validateTokenAlgo(token *jwt.JSONWebToken, algo jose.SignatureAlgorithm) error {
	h, err := header(token)
	if err != nil {
		return err
	}

	return validateHeaderAlgo(h, algo)
}
