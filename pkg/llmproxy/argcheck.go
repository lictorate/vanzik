package llmproxy

// Duplicate-JSON-key detection (parser-differential bypass). The gate
// reads arguments through a Go map, where the last duplicate wins, but
// ALLOW replays the raw bytes, and a first-wins executor would act on a
// value that was never gated. runPolicyCheck refuses such arguments.

import (
	"bytes"
	"encoding/json"
	"errors"
)

var errDuplicateJSONKey = errors.New("duplicate json key")

// hasDuplicateJSONKeys reports whether any object in raw, at any depth,
// repeats a key. Empty or invalid JSON returns false unless a duplicate
// was already seen: malformed arguments are handled elsewhere.
func hasDuplicateJSONKeys(raw []byte) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	return errors.Is(walkForDuplicateKeys(dec), errDuplicateJSONKey)
}

// walkForDuplicateKeys consumes one JSON value from dec. It returns
// errDuplicateJSONKey on a repeated key, or the decoder's error.
func walkForDuplicateKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("non-string object key")
			}
			if _, dup := seen[key]; dup {
				return errDuplicateJSONKey
			}
			seen[key] = struct{}{}
			if err := walkForDuplicateKeys(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	case '[':
		for dec.More() {
			if err := walkForDuplicateKeys(dec); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}
