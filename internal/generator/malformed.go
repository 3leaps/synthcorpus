package generator

import (
	"context"
	"os"
	"path/filepath"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

func generateMalformed(_ context.Context, root string, _ Runner, manifest *Manifest) error {
	dir := filepath.Join(root, "malformed")
	specimens := map[string]string{
		"gpg-truncated.asc": `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: synthcorpus generated-real malformed TEST KEY - DO NOT USE

not-a-complete-packet
-----END PGP PRIVATE KEY BLOCK-----
`,
		"minisign-truncated.key": `untrusted comment: synthcorpus generated-real malformed TEST KEY - DO NOT USE
RWRub3QtYS1taW5pc2lnbi1rZXk=
`,
		"ssh-truncated": `-----BEGIN OPENSSH PRIVATE KEY-----
synthcorpus generated-real malformed TEST KEY - DO NOT USE
-----END OPENSSH PRIVATE KEY-----
`,
	}
	for name, body := range specimens {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), guardrail.SecretPerm); err != nil {
			return err
		}
		appendArtifact(manifest, "malformed", "edge", rel(root, path))
	}
	return nil
}
