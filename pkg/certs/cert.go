package certs

import (
	"encoding/pem"
	"fmt"
	"strings"
)

// Split a single string of multiple certs into multiple strings of single
// certs.
func Split(certs string) []string {
	var res []string
	for block, data := pem.Decode([]byte(certs)); block != nil; block, data = pem.Decode(data) {
		res = append(res, string(pem.EncodeToMemory(block)))
	}
	return res
}

// Parse the environment variables satsifying the pattern and construct a list
// of certs.
func Parse(pattern string, environ []string) (string, int, error) {
	envVars := map[string]string{}
	for _, e := range environ {
		parts := strings.SplitN(e, "=", 2)
		envVars[parts[0]] = parts[1]
	}

	var certs string
	for i := 0; ; i++ {
		name := fmt.Sprintf("%s_%d", pattern, i)
		fragment, found := envVars[name]
		if !found {
			return certs, i, nil
		}

		block, _ := pem.Decode([]byte(fragment))
		if block == nil {
			return "", i, fmt.Errorf("cert not in pem format")
		}

		certs += fragment
	}
}
