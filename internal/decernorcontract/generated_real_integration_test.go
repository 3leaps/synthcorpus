//go:build contract && sidecars

package decernorcontract

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/3leaps/synthcorpus/internal/decernorloc"
	"github.com/3leaps/synthcorpus/internal/generator"
)

func TestGeneratedRealProperties(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	repo := repoRoot(t)
	binary, err := ResolvePinnedBinary(ctx, repo, os.Getenv(decernorloc.EnvBinary))
	if err != nil {
		t.Fatal(err)
	}

	parentBase := ""
	if runtime.GOOS == "darwin" {
		// Keep GNUPGHOME below macOS's short AF_UNIX socket-path limit. The
		// generator canonicalizes /tmp to /private/tmp before its git checks.
		parentBase = "/tmp"
	}
	parent, err := os.MkdirTemp(parentBase, "sc-contract-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Errorf("remove generated-real test parent: %v", err)
		}
	})
	corpusRoot := filepath.Join(parent, "generated-real")
	if err := generator.Generate(ctx, generator.Options{Tool: "decernor", Out: corpusRoot}); err != nil {
		t.Fatal(err)
	}
	if err := CheckGeneratedReal(ctx, repo, corpusRoot, binary); err != nil {
		t.Fatal(err)
	}
}
