package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("ca bundle %q did not contain any certificates", path)
	}
	return pool, nil
}
