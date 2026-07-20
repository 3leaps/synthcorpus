package provability

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestClosedFixtureInventory(t *testing.T) {
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	want, err := RegistryPaths()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]struct{}{}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("symlink not allowed in fixtures: %s", rel)
			return nil
		}
		if !info.Mode().IsRegular() {
			t.Errorf("non-regular file not allowed in fixtures: %s mode=%v", rel, info.Mode())
			return nil
		}
		// Exact documentation path only (not any nested README.md).
		if rel == "README.md" {
			return nil
		}
		if _, ok := want[rel]; !ok {
			t.Errorf("unregistered fixture file: %s", rel)
		}
		got[rel] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for rel := range want {
		if _, ok := got[rel]; !ok {
			t.Errorf("missing registered fixture: %s", rel)
		}
	}
}

func TestNoGeneratedRealMarkersInFixtures(t *testing.T) {
	root, err := FixturesRoot()
	if err != nil {
		t.Fatal(err)
	}
	// Coverage for ProofNoGeneratedRealMarker on every registry path.
	for _, f := range FixturesWithProof(ProofNoGeneratedRealMarker) {
		data, err := os.ReadFile(filepath.Join(root, f.Rel))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("synthcorpus-generated-real")) ||
			bytes.Contains(data, []byte(".synthcorpus-generated-real")) {
			t.Errorf("generated-real marker in %s", f.Rel)
		}
	}
	// Whole-tree sweep for non-registry docs too.
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("synthcorpus-generated-real")) {
			t.Errorf("generated-real marker in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
