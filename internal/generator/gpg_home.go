package generator

import (
	"context"
	"fmt"
	"path/filepath"
)

// macOS AF_UNIX sun_path is 104 bytes (including the trailing NUL on some
// kernels). Default agent socket lives at $GNUPGHOME/S.gpg-agent (13-byte
// suffix including the separator). Budget the home path so
// home+"/S.gpg-agent" stays safely under the limit with a few bytes of slack.
//
// 104 - 13 (socket) - 1 (NUL) - slack → keep homes ≤ 80 when create-socketdir
// is unavailable. Historical long staging names under ~/dev/dogfooding reached
// ~88 chars and gpg-agent failed to start on macOS without /run/user.
const maxGNUPGHomeWithoutSocketdir = 80

// prepareGPGHome ensures the isolated home is ready for agent use. Deep
// output paths fail closed unless gpgconf can create a short socketdir —
// never leave a half-generated corpus after agent socket failures mid-mint.
//
// Isolation rule: GNUPGHOME is always under the corpus root (never the user
// default keyring). create-socketdir may place sockets under a short system
// path when available; that is still scoped to this --homedir, not ~/.gnupg.
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
