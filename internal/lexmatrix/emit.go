package lexmatrix

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

// FixtureFile is the sterile fixture set's filename inside an output root.
const FixtureFile = "fixtures.json"

// ManifestFile is the protected manifest's filename inside an output root.
const ManifestFile = "manifest.json"

// AccountingFile is the floor-evidence filename inside an output root.
const AccountingFile = "accounting.json"

// SourcesDir holds the protected source artifacts inside an output root.
const SourcesDir = "sources"

// WriteResult reports what a write produced, so a caller can record digests
// without re-reading the files.
type WriteResult struct {
	Root           string
	FixtureSHA256  string
	ManifestSHA256 string
	CaseCount      int
	SourceCount    int
	TermCount      int
	CandidateCount int
}

// canonicalJSON is the single encoding used for both digesting and writing, so
// a recorded digest always matches the bytes on disk.
func canonicalJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func canonicalDigest(v any) (string, error) {
	data, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// Write publishes a generated corpus under root. The protected manifest and
// source artifacts are written alongside the sterile fixture set, so the whole
// root inherits the protected posture: it must never sit inside a git
// worktree, and only the fixture set is safe to move out of it.
func Write(root string, res *Result, force bool) (WriteResult, error) {
	final, err := guardrail.ResolveOutputPathFor(root, outputSubject)
	if err != nil {
		return WriteResult{}, err
	}

	occupied, err := dirHasEntries(final)
	if err != nil {
		return WriteResult{}, err
	}
	if occupied {
		if !force {
			return WriteResult{}, fmt.Errorf("output root already exists; use --force only for a marker-owned lexical corpus: %s", final)
		}
		// Establish ownership before writing anything, so a run that is going
		// to be refused is refused before it does any work.
		if err := guardrail.CheckOwnedMarkerFor(final, guardrail.MarkerLexicalCorpus); err != nil {
			return WriteResult{}, err
		}
	}

	// Build the replacement beside the target and swap it in at the end. A
	// corpus takes hundreds of files to write, and any failure part-way through
	// a destructive in-place write would leave the previous good corpus gone
	// and its replacement incomplete.
	abs, err := guardrail.PrepareOutputRootFor(final+".staging", true, outputSubject, guardrail.MarkerLexicalCorpus)
	if err != nil {
		return WriteResult{}, err
	}
	// The marker goes down first: it is what makes an interrupted staging
	// directory reclaimable by the next run.
	if err := guardrail.WriteMarkerFor(abs, "lexmatrix", guardrail.MarkerLexicalCorpus); err != nil {
		return WriteResult{}, fmt.Errorf("write ownership marker: %w", err)
	}

	manifestBytes, err := canonicalJSON(res.Manifest)
	if err != nil {
		return WriteResult{}, err
	}
	manifestSum := sha256.Sum256(manifestBytes)
	manifestDigest := hex.EncodeToString(manifestSum[:])
	if manifestDigest != res.Fixtures.SourceManifestSHA256 {
		return WriteResult{}, fmt.Errorf("manifest digest %s does not match the digest recorded in the fixture set (%s)",
			manifestDigest, res.Fixtures.SourceManifestSHA256)
	}

	sourcesRoot := filepath.Join(abs, SourcesDir)
	if err := os.MkdirAll(sourcesRoot, guardrail.DirPerm); err != nil {
		return WriteResult{}, fmt.Errorf("create sources directory: %w", err)
	}

	ids := make([]string, 0, len(res.Artifacts))
	for id := range res.Artifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		path := filepath.Join(sourcesRoot, id+".txt")
		if err := os.WriteFile(path, []byte(res.Artifacts[id]), guardrail.SecretPerm); err != nil {
			return WriteResult{}, fmt.Errorf("write source artifact %s: %w", id, err)
		}
	}

	if err := os.WriteFile(filepath.Join(abs, ManifestFile), manifestBytes, guardrail.SecretPerm); err != nil {
		return WriteResult{}, fmt.Errorf("write manifest: %w", err)
	}

	fixtureBytes, err := canonicalJSON(res.Fixtures)
	if err != nil {
		return WriteResult{}, err
	}
	if err := os.WriteFile(filepath.Join(abs, FixtureFile), fixtureBytes, guardrail.SecretPerm); err != nil {
		return WriteResult{}, fmt.Errorf("write fixture set: %w", err)
	}
	fixtureSum := sha256.Sum256(fixtureBytes)

	accountingBytes, err := canonicalJSON(res.Accounting)
	if err != nil {
		return WriteResult{}, err
	}
	if err := os.WriteFile(filepath.Join(abs, AccountingFile), accountingBytes, guardrail.SecretPerm); err != nil {
		return WriteResult{}, fmt.Errorf("write accounting: %w", err)
	}

	if err := publish(abs, final); err != nil {
		return WriteResult{}, err
	}

	return WriteResult{
		Root:           final,
		FixtureSHA256:  hex.EncodeToString(fixtureSum[:]),
		ManifestSHA256: manifestDigest,
		CaseCount:      len(res.Fixtures.Cases),
		SourceCount:    len(res.Manifest.Sources),
		TermCount:      len(res.Manifest.Terms),
		CandidateCount: res.Fixtures.LexicalCandidateCount,
	}, nil
}

// outputSubject is the wording the path guards use when refusing.
const outputSubject = "a generated lexical corpus"

// dirHasEntries reports whether path is a directory holding anything.
func dirHasEntries(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect output root: %w", err)
	}
	return len(entries) > 0, nil
}

// publish swaps a completed staging root into place, keeping the previous
// corpus intact until the replacement is fully in position.
func publish(staging, final string) error {
	previous := final + ".previous"
	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("clear stale previous corpus: %w", err)
	}

	replacing, err := dirHasEntries(final)
	if err != nil {
		return err
	}
	if replacing {
		if err := os.Rename(final, previous); err != nil {
			return fmt.Errorf("set previous corpus aside: %w", err)
		}
	} else if err := os.RemoveAll(final); err != nil {
		return fmt.Errorf("clear empty output root: %w", err)
	}

	if err := os.Rename(staging, final); err != nil {
		if replacing {
			// Put the previous corpus back rather than leaving nothing.
			if rollback := os.Rename(previous, final); rollback != nil {
				return fmt.Errorf("publish corpus: %w (and the previous corpus is left at %s: %v)", err, previous, rollback)
			}
		}
		return fmt.Errorf("publish corpus: %w", err)
	}

	if err := os.RemoveAll(previous); err != nil {
		return fmt.Errorf("remove previous corpus: %w", err)
	}
	return nil
}

// FixtureDigest returns the digest the sterile fixture set will carry on disk.
func FixtureDigest(res *Result) (string, error) {
	return canonicalDigest(res.Fixtures)
}
