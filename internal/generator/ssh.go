package generator

import (
	"context"
	"path/filepath"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

func generateSSH(ctx context.Context, root string, runner Runner, manifest *Manifest) error {
	dir := filepath.Join(root, "ssh")
	protectedKey := filepath.Join(dir, "id_ed25519_protected")
	plainKey := filepath.Join(dir, "id_ed25519_plain")
	comment := "synthcorpus generated-real TEST KEY - DO NOT USE <" + testEmail + ">"

	if err := runner.Run(ctx, "ssh-keygen", []string{"-q", "-t", "ed25519", "-f", protectedKey, "-N", KnownPassphrase, "-C", comment}, sidecarEnv(root), ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "ssh-keygen", []string{"-q", "-t", "ed25519", "-f", plainKey, "-N", "", "-C", comment}, sidecarEnv(root), ""); err != nil {
		return err
	}

	if err := chmodFile(protectedKey, guardrail.SecretPerm); err != nil {
		return err
	}
	if err := chmodFile(plainKey, guardrail.SecretPerm); err != nil {
		return err
	}
	if err := chmodFile(protectedKey+".pub", guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(plainKey+".pub", guardrail.PublicPerm); err != nil {
		return err
	}

	appendArtifact(manifest, "ssh", "private-protected", rel(root, protectedKey))
	appendArtifact(manifest, "ssh", "public", rel(root, protectedKey+".pub"))
	appendArtifact(manifest, "ssh", "private-plain", rel(root, plainKey))
	appendArtifact(manifest, "ssh", "public", rel(root, plainKey+".pub"))
	return nil
}
