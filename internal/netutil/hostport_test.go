package netutil

import "testing"

func TestSplitHostPortHandlesIPv6(t *testing.T) {
	tests := []struct {
		authority string
		wantHost  string
		wantPort  uint16
	}{
		{authority: "[2001:db8::1]:8443", wantHost: "2001:db8::1", wantPort: 8443},
		{authority: "[2001:db8::1]", wantHost: "2001:db8::1", wantPort: 443},
		{authority: "2001:db8::1", wantHost: "2001:db8::1", wantPort: 443},
		{authority: "example.test:9443", wantHost: "example.test", wantPort: 9443},
	}
	for _, tt := range tests {
		t.Run(tt.authority, func(t *testing.T) {
			host, port, err := SplitHostPort(tt.authority, 443)
			if err != nil {
				t.Fatal(err)
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("SplitHostPort() = %q, %d; want %q, %d", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}
