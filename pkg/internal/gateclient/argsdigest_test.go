package gateclient

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// ArgsDigest is what binds an approval to a tool call's arguments: a
// retry that re-serialises the same call must match, any other call must not.
func TestArgsDigest(t *testing.T) {
	k := NewArgsDigestKey("test-key")
	key := k[:]
	cases := []struct {
		name         string
		toolA, argsA string
		toolB, argsB string
		same         bool
	}{
		{"identical", "send_email", `{"to":"a@example.com","body":"hi"}`, "send_email", `{"to":"a@example.com","body":"hi"}`, true},
		{"reordered keys and whitespace", "send_email", `{"to":"a@example.com","body":"hi","opts":{"x":1,"y":[1,2]}}`,
			"send_email", "{ \"opts\" : {\"y\":[1, 2], \"x\":1},\n\t\"body\":\"hi\", \"to\":\"a@example.com\" }", true},
		{"swapped argument", "send_email", `{"to":"a@example.com","body":"hi"}`, "send_email", `{"to":"m@example.com","body":"hi"}`, false},
		{"redaction-equal secrets", "bash", `{"command":"psql password=one"}`, "bash", `{"command":"psql password=two"}`, false},
		{"other tool", "send_email", `{"to":"a@example.com"}`, "send_sms", `{"to":"a@example.com"}`, false},
		{"integers above 2^53", "pay", `{"amount":9007199254740993}`, "pay", `{"amount":9007199254740992}`, false},
		{"number spelling", "pay", `{"amount":1}`, "pay", `{"amount":1.0}`, false},
		{"invalid JSON", "t", `{"a":1`, "t", `{"a":2`, false},
		{"invalid JSON vs its valid prefix", "t", `{"a":1} {"a":2}`, "t", `{"a":1}`, false},
		{"invalid UTF-8", "t", "{\"a\":\"\xff\"}", "t", "{\"a\":\"\xfe\"}", false},
		{"empty vs empty object", "t", ``, "t", `{}`, false},
		{"tool name boundary", "ab", `{}`, "a", `b{}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ArgsDigest(key, c.toolA, []byte(c.argsA))
			b := ArgsDigest(key, c.toolB, []byte(c.argsB))
			if (a == b) != c.same {
				t.Errorf("digests equal = %v, want %v (%s vs %s)", a == b, c.same, a, b)
			}
			if raw, err := hex.DecodeString(a); err != nil || len(raw) != 32 {
				t.Errorf("digest %q is not hex HMAC-SHA256", a)
			}
		})
	}
}

// Gates sharing an API key derive one key, so an approval survives a gate
// restart; without an API key each process has its own.
func TestNewArgsDigestKey(t *testing.T) {
	k1, k2 := NewArgsDigestKey("k1"), NewArgsDigestKey("k2")
	if k1 != NewArgsDigestKey("k1") {
		t.Error("same API key gave different digest keys")
	}
	if k1 == k2 {
		t.Error("different API keys gave the same digest key")
	}
	if bytes.HasPrefix(k1[:], []byte("k1")) {
		t.Error("digest key is the API key itself")
	}
	a, b := NewArgsDigestKey(""), NewArgsDigestKey("")
	if a == b || a == [32]byte{} {
		t.Errorf("without an API key, want two distinct random keys; got %x, %x", a, b)
	}
	args := []byte(`{"pin":"1234"}`)
	if ArgsDigest(k1[:], "t", args) == ArgsDigest(k2[:], "t", args) {
		t.Error("digest does not depend on the key")
	}
}
