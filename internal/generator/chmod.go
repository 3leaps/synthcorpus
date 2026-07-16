package generator

import (
	"fmt"
	"os"
)

// chmodFile sets permissions and fails closed on error. Artifact modes are
// part of the ceremony evidence contract (secrets 0600, public 0644).
func chmodFile(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s to %#o: %w", path, mode, err)
	}
	return nil
}
