package generator

import (
	"context"
	"fmt"
	"path/filepath"
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
	// (AF_UNIX sun_path ~104 bytes). Many macOS hosts lack /run/user, so
	// create-socketdir may fail even for short homes — that is OK when
	// GNUPGHOME itself fits the socket budget (in-home S.gpg-agent).
	// Fail closed only when the path is too long for in-home sockets.
	if err := runner.Run(ctx, "gpgconf", []string{"--homedir", home, "--create-socketdir"}, env, ""); err != nil {
		if len(home) > maxGNUPGHomeWithoutSocketdir {
			return fmt.Errorf("gpg agent socket setup failed for GNUPGHOME %q (len=%d > %d; deep paths require working gpgconf --create-socketdir): %w", home, len(home), maxGNUPGHomeWithoutSocketdir, err)
		}
		// Short homes: fall back to in-home agent sockets (common on macOS
		// without /run/user).
	}
	return nil
}
