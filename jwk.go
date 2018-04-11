package authkit

// This file contains JWK utilities, such as client for a remote JWK Set.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	// ErrJWKNotFound informs that JWK was not found.
	ErrJWKNotFound = errors.New("JWK not found")
)

// JSONWebKeyer can provide a JWK for a JWT.
type JSONWebKeyer interface {
	JSONWebKeyForToken(token *jwt.JSONWebToken) (jose.JSONWebKey, error)
}

// JWKSClient represents a client for a remote JWK Set.
type JWKSClient struct {
	url string

	// cache is an internal cache for JWKs.
	// It maps JWK id to JWK.
	cache map[string]jose.JSONWebKey

	mu sync.Mutex
}

// JSONWebKey returns a JWK by its id.
func (c *JWKSClient) JSONWebKey(ID string) (jose.JSONWebKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.cache[ID]; ok {
		return key, nil
	}

	// Download keys

	if err := c.fetch(); err != nil {
		return jose.JSONWebKey{}, err
	}

	if key, ok := c.cache[ID]; ok {
		return key, nil
	}

	return jose.JSONWebKey{}, ErrJWKNotFound
}

// JSONWebKeyForToken returns a JWK for the token.
func (c *JWKSClient) JSONWebKeyForToken(token *jwt.JSONWebToken) (jose.JSONWebKey, error) {
	hdr, err := header(token)
	if err != nil {
		return jose.JSONWebKey{}, err
	}

	if err = validateHeaderAlgo(hdr, jose.RS256); err != nil {
		return jose.JSONWebKey{}, err
	}

	return c.JSONWebKey(hdr.KeyID)
}

func (c *JWKSClient) fetch() error {
	res, err := http.Get(c.url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	ct := res.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		return errors.New("remote JWK Set is not a JSON object")
	}

	var jwkset jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&jwkset); err != nil {
		return err
	}

	for _, k := range jwkset.Keys {
		c.cache[k.KeyID] = k
	}

	return nil
}

// NewJWKSClient returns a new client for a remote JWK Set represented by url.
func NewJWKSClient(url string) *JWKSClient {
	return &JWKSClient{
		url:   url,
		cache: make(map[string]jose.JSONWebKey),
	}
}
