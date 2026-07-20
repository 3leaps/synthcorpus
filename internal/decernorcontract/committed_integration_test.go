//go:build contract

package decernorcontract

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/3leaps/synthcorpus/internal/decernorloc"
)

func TestCommittedSyntheticGolden(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := CheckCommittedSynthetic(ctx, repoRoot(t), os.Getenv(decernorloc.EnvBinary)); err != nil {
		t.Fatal(err)
	}
}
