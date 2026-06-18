// Package netutil contains small network parsing helpers shared across Airlock packages.
package netutil

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SplitHostPort parses an authority into host and port, using defaultPort when
// the authority omits a port.
func SplitHostPort(authority string, defaultPort uint16) (string, uint16, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", 0, fmt.Errorf("destination host is required")
	}
	if host, portText, err := net.SplitHostPort(authority); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", 0, fmt.Errorf("destination host is required")
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("destination port is invalid")
		}
		return strings.Trim(host, "[]"), uint16(port), nil
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		host := strings.Trim(authority, "[]")
		if strings.TrimSpace(host) == "" {
			return "", 0, fmt.Errorf("destination host is required")
		}
		return host, defaultPort, nil
	}
	if strings.Count(authority, ":") > 1 {
		return strings.Trim(authority, "[]"), defaultPort, nil
	}
	host, portText, ok := strings.Cut(authority, ":")
	if ok {
		if host == "" || !allDigits(portText) {
			return "", 0, fmt.Errorf("destination port is invalid")
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("destination port is invalid")
		}
		return host, uint16(port), nil
	}
	return authority, defaultPort, nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
