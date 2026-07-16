package generator

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

func generateGPG(ctx context.Context, root string, runner Runner, manifest *Manifest) error {
	dir := filepath.Join(root, "gpg")
	protectedBatch := filepath.Join(dir, "gpg-protected.batch")
	plainBatch := filepath.Join(dir, "gpg-plain.batch")

	protected := fmt.Sprintf(`%%echo generating protected synthcorpus test key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: %s
Name-Email: %s
Expire-Date: 0
Passphrase: %s
%%commit
%%echo done
`, testName, testEmail, KnownPassphrase)
	plain := fmt.Sprintf(`%%echo generating plain synthcorpus test key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: %s plain
Name-Email: plain.%s
Expire-Date: 0
%%no-protection
%%commit
%%echo done
`, testName, testEmail)

	if err := os.WriteFile(protectedBatch, []byte(protected), guardrail.SecretPerm); err != nil {
		return err
	}
	defer os.Remove(protectedBatch)
	if err := os.WriteFile(plainBatch, []byte(plain), guardrail.SecretPerm); err != nil {
		return err
	}
	defer os.Remove(plainBatch)

	env := sidecarEnv(root)
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", filepath.Join(root, ".gnupg"), "--generate-key", protectedBatch}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", filepath.Join(root, ".gnupg"), "--generate-key", plainBatch}, env, ""); err != nil {
		return err
	}

	publicPath := filepath.Join(dir, "public.asc")
	protectedSecretPath := filepath.Join(dir, "private-protected.asc")
	plainSecretPath := filepath.Join(dir, "private-plain.asc")
	signaturePath := filepath.Join(dir, "sample.txt.asc")
	revocationPath := filepath.Join(dir, "revocation.asc")

	if err := runner.Run(ctx, "gpg", []string{"--batch", "--homedir", filepath.Join(root, ".gnupg"), "--output", publicPath, "--armor", "--export", testEmail}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", filepath.Join(root, ".gnupg"), "--passphrase", KnownPassphrase, "--output", protectedSecretPath, "--armor", "--export-secret-keys", testEmail}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--homedir", filepath.Join(root, ".gnupg"), "--output", plainSecretPath, "--armor", "--export-secret-keys", "plain." + testEmail}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--yes", "--pinentry-mode", "loopback", "--homedir", filepath.Join(root, ".gnupg"), "--passphrase", KnownPassphrase, "--local-user", testEmail, "--output", signaturePath, "--armor", "--detach-sign", filepath.Join(root, "sample.txt")}, env, ""); err != nil {
		return err
	}
	if err := copyFirstRevocation(filepath.Join(root, ".gnupg", "openpgp-revocs.d"), revocationPath); err != nil {
		return err
	}

	_ = os.Chmod(publicPath, guardrail.PublicPerm)
	_ = os.Chmod(protectedSecretPath, guardrail.SecretPerm)
	_ = os.Chmod(plainSecretPath, guardrail.SecretPerm)
	_ = os.Chmod(signaturePath, guardrail.PublicPerm)
	_ = os.Chmod(revocationPath, guardrail.PublicPerm)

	appendArtifact(manifest, "gpg", "public", rel(root, publicPath))
	appendArtifact(manifest, "gpg", "private-protected", rel(root, protectedSecretPath))
	appendArtifact(manifest, "gpg", "private-plain", rel(root, plainSecretPath))
	appendArtifact(manifest, "gpg", "signature", rel(root, signaturePath))
	appendArtifact(manifest, "gpg", "revocation", rel(root, revocationPath))
	return nil
}

func copyFirstRevocation(srcDir, dst string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read GPG revocation directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		src := filepath.Join(srcDir, entry.Name())
		in, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open GPG revocation certificate: %w", err)
		}
		defer in.Close()

		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, guardrail.PublicPerm)
		if err != nil {
			return fmt.Errorf("create GPG revocation artifact: %w", err)
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return fmt.Errorf("copy GPG revocation artifact: %w", err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("close GPG revocation artifact: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no GPG revocation certificate generated in %s", srcDir)
}
