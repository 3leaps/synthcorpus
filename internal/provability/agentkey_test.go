package provability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAgentKeyInventoryMatchesManifest reconciles fixtures-agent/ and the
// verdict manifest in both directions, and pins each file's digest.
func TestAgentKeyInventoryMatchesManifest(t *testing.T) {
	root, err := AgentKeyFixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadAgentKeyManifest()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("symlink not allowed: %s", path)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "README.md" {
			return nil
		}
		entry, ok := m.Fixtures[rel]
		if !ok {
			t.Errorf("fixture not in manifest: %s", rel)
			return nil
		}
		seen[rel] = true
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			t.Errorf("%s: digest drift; update the manifest deliberately", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range m.Fixtures {
		if !seen[rel] {
			t.Errorf("manifest entry has no file: %s", rel)
		}
	}
}

var (
	// Advanced-form parameter values: #hex#, |base64|, or a bare token.
	agentParamList = regexp.MustCompile(`\(([a-z])\s+(#[0-9A-Fa-f]*#|\|[A-Za-z0-9+/=]*\||[^()\s]+)\)`)
	// Canonical-form key parameter lists: (1:<name><len>:<value>), where the
	// name is a key parameter letter. Shadow-info lists hold a serial atom,
	// not a parameter, and are excluded by the name set.
	agentCanonicalParam = regexp.MustCompile(`\(1:([nedpqugyxk])(\d+):`)
)

// TestAgentKeyParametersArePlaceholders proves no fixture can be a usable key:
// every key parameter value is a placeholder (all-zero hex, "x", or a short
// all-zero base64), never key-sized material.
func TestAgentKeyParametersArePlaceholders(t *testing.T) {
	root, err := AgentKeyFixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadAgentKeyManifest()
	if err != nil {
		t.Fatal(err)
	}
	for rel := range m.Fixtures {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range agentParamList.FindAllSubmatch(data, -1) {
			if !isPlaceholderValue(string(match[2])) {
				t.Errorf("%s: parameter %q has non-placeholder value %q", rel, match[1], match[2])
			}
		}
		for _, loc := range agentCanonicalParam.FindAllSubmatchIndex(data, -1) {
			n := 0
			for _, c := range data[loc[4]:loc[5]] {
				n = n*10 + int(c-'0')
			}
			start := loc[1]
			if n > 1 || start+n > len(data) || (n == 1 && data[start] != 'x') {
				t.Errorf("%s: canonical parameter %q has non-placeholder value", rel, data[loc[2]:loc[3]])
			}
		}
		if bytes.Count(data, []byte("#")) > 0 {
			for _, h := range regexp.MustCompile(`#([0-9A-Fa-f]+)#`).FindAllSubmatch(data, -1) {
				// Token spellings (e.g. a hex-encoded outer token) are names, not values.
				if len(h[1]) > 4 && !isAgentTokenHex(string(h[1])) {
					t.Errorf("%s: hex atom %q exceeds placeholder size", rel, h[1])
				}
			}
		}
	}
}

func isPlaceholderValue(v string) bool {
	switch {
	case v == "x":
		return true
	case strings.HasPrefix(v, "#") && strings.HasSuffix(v, "#"):
		body := v[1 : len(v)-1]
		return len(body) <= 4 && strings.Trim(body, "0") == ""
	case strings.HasPrefix(v, "|") && strings.HasSuffix(v, "|"):
		return v == "|AA==|" || v == "|ZA==|"
	}
	// Bare tokens such as curve or shadow-type names carry no key material.
	return len(v) <= 32 && !strings.ContainsAny(v, "0123456789") || v == "t1-v1" || v == "tpm2-v1"
}

func isAgentTokenHex(h string) bool {
	b, err := hex.DecodeString(h)
	if err != nil {
		return false
	}
	switch string(b) {
	case "private-key", "protected-private-key", "shadowed-private-key":
		return true
	}
	return false
}

// TestAgentKeyClassInvariantsUseDeclaredRules asserts every class has
// invariants, every invariant names a declared rule, and every fixture class
// has invariants.
func TestAgentKeyClassInvariantsUseDeclaredRules(t *testing.T) {
	m, err := LoadAgentKeyManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.InvariantRules) == 0 {
		t.Fatal("manifest declares no invariant rules")
	}
	for class, rules := range m.ClassInvariants {
		if len(rules) == 0 {
			t.Errorf("class %s has no invariants", class)
		}
		for _, rule := range rules {
			if _, ok := m.InvariantRules[rule]; !ok {
				t.Errorf("class %s names undeclared rule %q", class, rule)
			}
		}
	}
	for rel, f := range m.Fixtures {
		if _, ok := m.ClassInvariants[f.Class]; !ok {
			t.Errorf("%s: class %q has no invariants", rel, f.Class)
		}
	}
}
