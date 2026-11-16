package gateclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// MetaArgsDigestKey is the /v1/check meta key carrying ArgsDigest. The
// central server compares it on an approval retry (matchesOriginalRequest)
// because the projected fields leave most arguments out and carry others
// redacted. Tool arguments land in meta as arg_<key>, so none can
// overwrite it.
const MetaArgsDigestKey = "args_digest"

// argsDigestLabel separates this use of the API key from any other HMAC
// keyed by it.
const argsDigestLabel = "vanzik/args-digest/v1"

// NewArgsDigestKey returns the key a gate digests arguments with. With an
// API key every gate process sharing it derives the same key, so an
// approval survives a gate restart and can be retried through another
// replica. Without one the key is random, so the digest still reveals
// nothing about low-entropy values (a short password) to readers of the
// audit log, at the cost of approvals not outliving the process.
//
// An array, not a slice, so the gate clients holding it stay comparable.
func NewArgsDigestKey(apiKey string) [32]byte {
	var k [32]byte
	if apiKey != "" {
		m := hmac.New(sha256.New, []byte(apiKey))
		m.Write([]byte(argsDigestLabel))
		copy(k[:], m.Sum(nil))
		return k
	}
	_, _ = rand.Read(k[:]) // never fails since Go 1.24
	return k
}

// ArgsDigest is the hex HMAC-SHA256, under key, of the tool name, a zero
// byte and the canonical arguments: decoded with UseNumber and re-encoded,
// so key order and whitespace don't matter but every digit of a number
// does. Arguments that don't decode are digested as they are.
func ArgsDigest(key []byte, toolName string, rawArgs []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(toolName))
	m.Write([]byte{0})
	m.Write(canonicalArgs(rawArgs))
	return hex.EncodeToString(m.Sum(nil))
}

func canonicalArgs(raw []byte) []byte {
	// The decoder replaces invalid UTF-8 with U+FFFD, which would give
	// different byte strings one digest.
	if !utf8.Valid(raw) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	// Trailing data would otherwise be dropped, giving `{} x` the digest of `{}`.
	if _, err := dec.Token(); err != io.EOF {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}
