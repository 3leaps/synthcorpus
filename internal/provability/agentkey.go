package provability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AgentKeyManifestPath is the expected-verdict manifest for fixtures-agent/.
const AgentKeyManifestPath = "manifests/decernor-scan-verdicts.json"

// AgentKeyFixture is one fixtures-agent/ entry from the verdict manifest.
type AgentKeyFixture struct {
	Class     string `json:"class"`
	Placement string `json:"placement"`
	Guardread string `json:"guardread"`
	SHA256    string `json:"sha256"`
}

// AgentKeyManifest is the subset of the verdict manifest provability needs.
type AgentKeyManifest struct {
	SchemaVersion   string                     `json:"schema_version"`
	Kind            string                     `json:"kind"`
	FixturesRoot    string                     `json:"fixtures_root"`
	InvariantRules  map[string]string          `json:"invariant_rules"`
	ClassInvariants map[string][]string        `json:"class_invariants"`
	Fixtures        map[string]AgentKeyFixture `json:"fixtures"`
}

// AgentKeyFixturesRoot resolves the committed fixtures-agent/ directory.
func AgentKeyFixturesRoot() (string, error) {
	return repoPath("fixtures-agent")
}

// LoadAgentKeyManifest reads and structurally checks the verdict manifest.
func LoadAgentKeyManifest() (AgentKeyManifest, error) {
	path, err := repoPath(AgentKeyManifestPath)
	if err != nil {
		return AgentKeyManifest{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return AgentKeyManifest{}, err
	}
	var m AgentKeyManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return AgentKeyManifest{}, err
	}
	if m.SchemaVersion != "v0" || m.Kind != "synthcorpus-decernor-scan-verdicts" || m.FixturesRoot != "fixtures-agent" {
		return AgentKeyManifest{}, fmt.Errorf("unexpected manifest header %q/%q/%q", m.SchemaVersion, m.Kind, m.FixturesRoot)
	}
	if len(m.Fixtures) == 0 {
		return AgentKeyManifest{}, fmt.Errorf("manifest lists no fixtures")
	}
	return m, nil
}

func repoPath(rel string) (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", filepath.FromSlash(rel)))
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}
