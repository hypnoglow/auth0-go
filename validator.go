package authkit

import (
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const algoRS256 = jose.RS256

// RS256Validator validates RS256 JWTs.
type RS256Validator struct {
	expectedClaims jwt.Expected
	keyer          JSONWebKeyer
}

// ValidClaims validates token and decodes its claims into dst if valid.
func (v *RS256Validator) ValidClaims(token string, dst ...interface{}) error {
	jsonWebToken, err := v.validToken(token)
	if err != nil {
		return err
	}

	return v.claims(jsonWebToken, dst...)
}

func (v *RS256Validator) validToken(t string) (*jwt.JSONWebToken, error) {
	token, err := jwt.ParseSigned(t)
	if err != nil {
		return nil, err
	}

	if err = validateTokenAlgo(token, algoRS256); err != nil {
		return nil, err
	}

	key, err := v.keyer.JSONWebKeyForToken(token)
	if err != nil {
		return nil, err
	}

	// Verify public claims.

	claims := jwt.Claims{}
	if err = token.Claims(key, &claims); err != nil {
		return nil, err
	}

	expected := v.expectedClaims.WithTime(time.Now())
	err = claims.Validate(expected)
	return token, err
}

func (v *RS256Validator) claims(token *jwt.JSONWebToken, values ...interface{}) error {
	key, err := v.keyer.JSONWebKeyForToken(token)
	if err != nil {
		return err
	}
	return token.Claims(key, values...)
}

// NewRS256Validator returns new validator for RS256 JWTs. It checks tokens for
// RS256 algorithm, audience, issuer, expiration, and uses keyer to retrieve
// public key to verify token signature.
func NewRS256Validator(audience, issuer string, keyer JSONWebKeyer) *RS256Validator {
	return &RS256Validator{
		expectedClaims: jwt.Expected{
			Issuer:   issuer,
			Audience: []string{audience},
		},
		keyer: keyer,
	}
}
