package worker

import (
	"fmt"
	"os"
	"strings"
)

type EnvFileSecretProvider struct{}

func (EnvFileSecretProvider) Resolve(ref SecretRef) (string, error) {
	switch ref.Provider {
	case "env":
		value, ok := os.LookupEnv(ref.Env)
		if !ok {
			return "", fmt.Errorf("environment secret %q is not set", ref.Env)
		}
		return value, nil
	case "file":
		data, err := os.ReadFile(ref.File)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	default:
		return "", fmt.Errorf("secret provider %q is not available in local mode", ref.Provider)
	}
}
