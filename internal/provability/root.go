package provability

import (
	"os"
	"path/filepath"
	"runtime"
)

// FixturesRoot resolves the committed fixtures/ directory from this package.
func FixturesRoot() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures"))
	st, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", os.ErrNotExist
	}
	return root, nil
}
