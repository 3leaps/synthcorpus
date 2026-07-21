package synthcorpus

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var embeddedVersion string

// Version returns the release version embedded from the repository VERSION file.
func Version() string {
	return strings.TrimSpace(embeddedVersion)
}
