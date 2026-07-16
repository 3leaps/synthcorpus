package generator

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
)

// macOS AF_UNIX sun_path is 104 bytes. Default agent socket lives at
// $GNUPGHOME/S.gpg-agent — leave headroom for the socket basename.
const maxGNUPGHomeWithoutSocketdir = 90

// prepareGPGHome ensures the isolated home is ready for agent use. Deep
// output paths fail closed unless gpgconf can create a short socketdir —
// never leave a half-generated corpus after agent socket failures mid-mint.
func prepareGPGHome(ctx context.Context, root string, runner Runner) error {
	home := filepath.Join(root, ".gnupg")
	env := sidecarEnv(root)

	// Prefer a short socket directory so deep dogfood roots work on macOS
	// (AF_UNIX sun_path ~104 bytes). Fail before any key mint when required.
	if err := runner.Run(ctx, "gpgconf", []string{"--homedir", home, "--create-socketdir"}, env, ""); err != nil {
		if len(home) > maxGNUPGHomeWithoutSocketdir || runtime.GOOS == "darwin" {
			return fmt.Errorf("gpg agent socket setup failed for GNUPGHOME %q (len=%d; macOS/deep paths require gpgconf --create-socketdir): %w", home, len(home), err)
		}
		// Short non-Darwin homes can fall back to in-home sockets.
	}
	return nil
}
