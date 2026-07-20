package provability

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func TestMinisignPublicCompleteInvalidEd25519Point(t *testing.T) {
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofMinisignInvalidPoint) {
		blob, err := readMinisignPublicBlob(filepath.Join(root, f.Rel))
		if err != nil {
			t.Fatalf("%s: %v", f.Rel, err)
		}
		if len(blob) != 42 {
			t.Fatalf("%s blob len=%d want 42", f.Rel, len(blob))
		}
		if blob[0] != 'E' || blob[1] != 'd' {
			t.Fatalf("%s prefix = %q want Ed", f.Rel, blob[:2])
		}
		// Also satisfy shape proof when co-declared.
		pub := blob[10:42]
		if _, err := new(edwards25519.Point).SetBytes(pub); err == nil {
			t.Fatalf("%s: expected Ed25519 SetBytes to reject public component", f.Rel)
		}
	}
	for _, f := range FixturesWithProof(ProofMinisignPublicShape) {
		if _, err := readMinisignPublicBlob(filepath.Join(root, f.Rel)); err != nil {
			t.Fatalf("%s: %v", f.Rel, err)
		}
	}
}

func TestMinisignPublicMalformedMarkerShape(t *testing.T) {
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofMinisignParseMarker) {
		data, err := os.ReadFile(filepath.Join(root, f.Rel))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.ToLower(string(data)), "minisign public key") {
			t.Fatalf("%s must carry historical public marker", f.Rel)
		}
		if _, err := readMinisignPublicBlob(filepath.Join(root, f.Rel)); err == nil {
			t.Fatalf("%s unexpectedly parsed as complete public blob", f.Rel)
		}
	}
}

func TestMinisignSecretBodiesAreNotValidSecrets(t *testing.T) {
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range FixturesWithProof(ProofMinisignSecretStruct) {
		data, err := os.ReadFile(filepath.Join(root, f.Rel))
		if err != nil {
			t.Fatal(err)
		}
		lines := nonEmptyLines(string(data))
		if len(lines) == 0 {
			t.Fatalf("%s empty", f.Rel)
		}
		var payload []string
		for _, ln := range lines {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ln)), "untrusted comment:") {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(ln), "#") {
				continue
			}
			payload = append(payload, strings.TrimSpace(ln))
		}
		if len(payload) == 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Join(payload, ""))
		if err == nil && len(raw) >= 40 {
			t.Fatalf("%s decoded to %d-byte body; truncated fixtures must not look like full secrets", f.Rel, len(raw))
		}
	}
}

func readMinisignPublicBlob(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var blobLine string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "untrusted comment:") {
			continue
		}
		if blobLine != "" {
			return nil, errNotComplete
		}
		blobLine = line
	}
	if blobLine == "" {
		return nil, errNotComplete
	}
	raw, err := base64.StdEncoding.DecodeString(blobLine)
	if err != nil {
		return nil, err
	}
	if len(raw) != 42 || raw[0] != 'E' || (raw[1] != 'd' && raw[1] != 'D') {
		return nil, errNotComplete
	}
	return raw, nil
}

var errNotComplete = os.ErrInvalid

func nonEmptyLines(text string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
