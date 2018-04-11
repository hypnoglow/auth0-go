package httpauth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/hypnoglow/authkit"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrTokenNotFound informs that token was not found.
	ErrTokenNotFound = errors.New("token not found")
)

// ExtractBearerToken returns bearer token from Authorization header of
// the HTTP request.
func ExtractBearerToken(req *http.Request) (string, error) {
	t, err := bearerToken(req)
	return string(t), err
}

// ExtractJSONWebToken returns JWT parsed from bearer token in Authorization
// header of the HTTP request.
// Returns ErrTokenNotFound if request doesn't have a bearer token.
func ExtractJSONWebToken(req *http.Request) (*jwt.JSONWebToken, error) {
	raw, err := bearerToken(req)
	if err != nil {
		return nil, err
	}
	return jwt.ParseSigned(string(raw))
}

// ExtractJSONWebKey returns JWK for the bearer token in Authorization header
// of the HTTP request.
// Returns ErrTokenNotFound if request doesn't have a bearer token.
func ExtractJSONWebKey(req *http.Request, keyer authkit.JSONWebKeyer) (jose.JSONWebKey, error) {
	token, err := ExtractJSONWebToken(req)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	return keyer.JSONWebKeyForToken(token)
}

func bearerToken(req *http.Request) ([]byte, error) {
	ah := req.Header.Get("Authorization")
	if len(ah) > 7 && strings.EqualFold(ah[0:7], "bearer ") {
		return []byte(ah[7:]), nil
	}
	return nil, ErrTokenNotFound
}
