package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const keyID = "airlock-compose-demo"

func main() {
	issuer := envOrDefault("OIDC_ISSUER", "http://oidc:8080")
	audience := envOrDefault("OIDC_AUDIENCE", "airlock-web")
	group := envOrDefault("OIDC_GROUP", "airlock-viewers")
	role := strings.TrimSpace(os.Getenv("OIDC_ROLE"))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":   issuer,
			"jwks_uri": issuer + "/keys",
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"keys": []map[string]any{rsaJWK(&key.PublicKey)},
		})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		tokenGroup := strings.TrimSpace(r.URL.Query().Get("group"))
		if tokenGroup == "" {
			tokenGroup = group
		}
		tokenRole := strings.TrimSpace(r.URL.Query().Get("role"))
		if tokenRole == "" {
			tokenRole = role
		}
		token, err := signJWT(key, issuer, audience, tokenGroup, tokenRole)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(token))
	})

	log.Printf("airlock-compose-oidc listening on :8080 issuer=%s audience=%s group=%s", issuer, audience, group)
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func signJWT(key *rsa.PrivateKey, issuer string, audience string, group string, role string) (string, error) {
	now := time.Now().UTC()
	header := map[string]any{
		"alg": "RS256",
		"kid": keyID,
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss":    issuer,
		"sub":    "compose-admin",
		"aud":    audience,
		"iat":    now.Unix(),
		"nbf":    now.Add(-time.Minute).Unix(),
		"exp":    now.Add(time.Hour).Unix(),
		"email":  "compose-admin@example.test",
		"groups": []string{group},
	}
	if role != "" {
		claims["roles"] = []string{role}
	}

	encodedHeader, err := jsonBase64(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := jsonBase64(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func rsaJWK(key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": keyID,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func jsonBase64(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOrDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}
