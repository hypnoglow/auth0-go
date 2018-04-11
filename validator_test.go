package authkit

import (
	"testing"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestRS256Validator_ValidClaims(t *testing.T) {
	testClaims := map[string]interface{}{
		"https://claims.example.com/username": "johndoe",
		"iss": "https://id.example.com/",
		"sub": "abcdef0123456789",
		"aud": []string{
			"https://api.example.com",
		},
		"iat":   1522994598,
		"exp":   1993180998,
		"azp":   "some-client-id",
		"scope": "openid offline_access",
		"gty":   "password",
	}

	token, err := jwt.Signed(testSigner).Claims(testClaims).CompactSerialize()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	v := NewRS256Validator(
		"https://api.example.com",
		"https://id.example.com/",
		fakeKeyer{},
	)

	var claims struct {
		Username string `json:"https://claims.example.com/username"`
	}

	if err := v.ValidClaims(token, &claims); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if claims.Username != "johndoe" {
		t.Fatalf("Expected claims username to be johndoe but got %s", claims.Username)
	}
}

type fakeKeyer struct{}

func (fakeKeyer) JSONWebKeyForToken(token *jwt.JSONWebToken) (jose.JSONWebKey, error) {
	return jose.JSONWebKey{
		Key: testPublicRSAKey,
	}, nil
}
