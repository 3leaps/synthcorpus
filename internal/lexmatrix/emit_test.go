package lexmatrix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

var (
	sharedOnce   sync.Once
	sharedResult *Result
	sharedErr    error
)

// sharedCorpus generates once for the whole test binary; the write tests care
// about publication, not about generating distinct corpora.
func sharedCorpus(t *testing.T) *Result {
	t.Helper()
	sharedOnce.Do(func() {
		sharedResult, sharedErr = Generate(Options{Seed: 7312026})
	})
	if sharedErr != nil {
		t.Fatalf("Generate: %v", sharedErr)
	}
	return sharedResult
}

func TestWritePublishesBothPlanes(t *testing.T) {
	res := sharedCorpus(t)
	root := filepath.Join(t.TempDir(), "corpus")

	written, err := Write(root, res, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The reported root is canonicalised — the guards resolve symlinks before
	// touching anything, and macOS temp paths go through /var -> /private/var.
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("canonicalise root: %v", err)
	}
	if written.Root != canonical {
		t.Fatalf("reported root %s, wrote to %s", written.Root, canonical)
	}

	for _, name := range []string{FixtureFile, ManifestFile, AccountingFile, guardrail.MarkerLexicalCorpus.Name} {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("expected %s in the output root: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != guardrail.SecretPerm {
			t.Fatalf("%s has mode %v, want %v", name, perm, os.FileMode(guardrail.SecretPerm))
		}
	}

	sources, err := os.ReadDir(filepath.Join(root, SourcesDir))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	if len(sources) != len(res.Manifest.Sources) {
		t.Fatalf("wrote %d source artifacts, manifest declares %d", len(sources), len(res.Manifest.Sources))
	}

	// The reported digest must be the digest of the bytes actually on disk,
	// since that is the number recorded downstream.
	fixtureBytes, err := os.ReadFile(filepath.Join(root, FixtureFile))
	if err != nil {
		t.Fatalf("read fixture set: %v", err)
	}
	sum := sha256.Sum256(fixtureBytes)
	if got := hex.EncodeToString(sum[:]); got != written.FixtureSHA256 {
		t.Fatalf("on-disk fixture digest %s, reported %s", got, written.FixtureSHA256)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(root, ManifestFile))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	manifestSum := sha256.Sum256(manifestBytes)
	if got := hex.EncodeToString(manifestSum[:]); got != res.Fixtures.SourceManifestSHA256 {
		t.Fatalf("on-disk manifest digest %s, fixture set claims %s", got, res.Fixtures.SourceManifestSHA256)
	}

	// The sterile plane must not carry a term value or a variant.
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	fixtureText := string(fixtureBytes)
	for _, term := range manifest.Terms {
		if len(term.Value) >= 6 && contains(fixtureText, term.Value) {
			t.Fatalf("term value %q leaked into the sterile fixture set", term.Value)
		}
	}
}

func TestWriteLeavesNoStagingOrPreviousBehind(t *testing.T) {
	res := sharedCorpus(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "corpus")

	if _, err := Write(root, res, false); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := Write(root, res, true); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read parent: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "corpus" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("publication left extra directories behind: %v", names)
	}
}

func TestWriteRefusesExistingRootWithoutForce(t *testing.T) {
	res := sharedCorpus(t)
	root := filepath.Join(t.TempDir(), "corpus")

	if _, err := Write(root, res, false); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := Write(root, res, false); err == nil {
		t.Fatal("a second Write without --force overwrote an existing corpus")
	}
}

// TestWriteRefusesForeignRoot is the destructive-blast-radius guard: the
// lexical lane must not replace a root another generator owns.
func TestWriteRefusesForeignRoot(t *testing.T) {
	res := sharedCorpus(t)
	root := filepath.Join(t.TempDir(), "decernor")

	if err := os.MkdirAll(root, guardrail.DirPerm); err != nil {
		t.Fatalf("create foreign root: %v", err)
	}
	if err := guardrail.WriteMarker(root, "decernor"); err != nil {
		t.Fatalf("write foreign marker: %v", err)
	}
	keyFile := filepath.Join(root, "id_ed25519")
	if err := os.WriteFile(keyFile, []byte("not a real key\n"), guardrail.SecretPerm); err != nil {
		t.Fatalf("seed foreign root: %v", err)
	}

	if _, err := Write(root, res, true); err == nil {
		t.Fatal("--force replaced a root owned by the generated-real lane")
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("refused write still destroyed the foreign root: %v", err)
	}
}

func TestWriteRefusesGitWorktree(t *testing.T) {
	res := sharedCorpus(t)
	repo := t.TempDir()

	cmd := exec.Command("git", "init", repo)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git init unavailable: %v (%s)", err, out)
	}

	if _, err := Write(filepath.Join(repo, "corpus"), res, false); err == nil {
		t.Fatal("Write published a corpus inside a git worktree")
	}
}

func TestWriteRejectsMismatchedManifestDigest(t *testing.T) {
	res := sharedCorpus(t)

	tampered := *res
	tampered.Fixtures = res.Fixtures
	tampered.Fixtures.SourceManifestSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	root := filepath.Join(t.TempDir(), "corpus")
	if _, err := Write(root, &tampered, false); err == nil {
		t.Fatal("Write published a fixture set whose manifest digest does not match the manifest")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
