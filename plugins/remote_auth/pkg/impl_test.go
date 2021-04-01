package pkg

import (
	"encoding/json"
	"fmt"
	"testing"
)



func TestExtractHeaders(t *testing.T) {
	body := "{\"userid\":\"123456\", \"isserver\": true, \"roles\": [\"admin\", \"user\"]}"
	attr := map[string]string{
		"userid": "x-auth-subject-id",
		"isserver": "x-auth-server-access",
		"roles": "x-auth-roles",
		"not-present": "x-auth-not-present",
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		t.Fatal(fmt.Errorf("unable to unmarshal test data: %v", err))
	}

	headers := extractHeaders(data, attr)
	expectations := map[string]string{
		"x-auth-subject-id": "123456",
		"x-auth-server-access": "true",
		"x-auth-roles": "admin,user",
	}
	if len(headers) != len(expectations) {
		t.Errorf("expect %v results, got %v", len(expectations), len(headers))
	}
	for header, expected := range expectations {
		var value string
		for _, h := range headers {
			if h.Header.Key == header {
				value = h.Header.Value
				break
			}
		}
		if value != expected {
			t.Errorf("expected header %v to have value %v, got %v", header, expected, value)
		}
	}
}
