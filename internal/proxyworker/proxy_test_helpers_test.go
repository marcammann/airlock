package proxyworker_test

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func readHTTPRequestBytes(r io.Reader) ([]byte, error) {
	var buffer []byte
	tmp := make([]byte, 4096)
	headerEnd := -1
	for headerEnd < 0 {
		n, err := r.Read(tmp)
		if err != nil {
			if err == io.EOF && len(buffer) > 0 {
				break
			}
			return nil, err
		}
		if n == 0 {
			continue
		}
		buffer = append(buffer, tmp[:n]...)
		if len(buffer) > maxHeaderBytes {
			return nil, fmt.Errorf("request headers exceed limit")
		}
		headerEnd = bytes.Index(buffer, []byte("\r\n\r\n"))
	}
	if headerEnd < 0 {
		return nil, fmt.Errorf("request headers missing terminator")
	}
	contentLength := testContentLength(buffer[:headerEnd])
	bodyStart := headerEnd + 4
	for len(buffer)-bodyStart < contentLength {
		n, err := r.Read(tmp)
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, tmp[:n]...)
	}
	return buffer[:bodyStart+contentLength], nil
}

func testContentLength(headerBytes []byte) int {
	for _, line := range strings.Split(string(headerBytes), "\r\n")[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			length, _ := strconv.Atoi(strings.TrimSpace(value))
			return length
		}
	}
	return 0
}
