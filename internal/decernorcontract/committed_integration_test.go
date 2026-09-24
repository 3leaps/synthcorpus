//go:build contract

package decernorcontract

import (
	"context"
	"testing"
	"time"
)

func TestCommittedSyntheticGolden(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := CheckCommittedSynthetic(ctx, repoRoot(t), ""); err != nil {
		t.Fatal(err)
	}
}
