//go:build contract

package decernorcontract

import (
	"context"
	"testing"
	"time"
)

func TestScanVerdicts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := CheckScanVerdicts(ctx, repoRoot(t), ""); err != nil {
		t.Fatal(err)
	}
}
