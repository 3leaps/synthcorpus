package generator

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

func generateGPG(ctx context.Context, root string, runner Runner, manifest *Manifest) error {
	if err := prepareGPGHome(ctx, root, runner); err != nil {
		return err
	}

	dir := filepath.Join(root, "gpg")
	protectedBatch := filepath.Join(dir, "gpg-protected.batch")
	plainBatch := filepath.Join(dir, "gpg-plain.batch")
	home := filepath.Join(root, ".gnupg")

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
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", home, "--generate-key", protectedBatch}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", home, "--generate-key", plainBatch}, env, ""); err != nil {
		return err
	}

	// Capture exact fingerprints — email substring selectors can match both
	// the protected UID and plain.<email>, exporting two keys into one artifact.
	fps, err := listSecretKeyFingerprints(ctx, root, runner)
	if err != nil {
		return err
	}
	protectedFP, err := fingerprintForEmail(fps, testEmail)
	if err != nil {
		return fmt.Errorf("protected gpg key: %w", err)
	}
	plainFP, err := fingerprintForEmail(fps, "plain."+testEmail)
	if err != nil {
		return fmt.Errorf("plain gpg key: %w", err)
	}
	if protectedFP == plainFP {
		return fmt.Errorf("protected and plain gpg keys resolved to the same fingerprint %s", protectedFP)
	}

	publicPath := filepath.Join(dir, "public.asc")
	protectedSecretPath := filepath.Join(dir, "private-protected.asc")
	plainSecretPath := filepath.Join(dir, "private-plain.asc")
	signaturePath := filepath.Join(dir, "sample.txt.asc")
	revocationPath := filepath.Join(dir, "revocation.asc")

	// public.asc intentionally bundles BOTH primary public keys (protected +
	// plain) for dogfood breadth. It is NOT the single-key protected secret
	// counterpart — secrets are exported separately by exact fingerprint only.
	// MANIFEST pairing (later) must label this as multi-key public, not as the
	// protected private's exclusive public twin.
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--homedir", home, "--output", publicPath, "--armor", "--export", protectedFP, plainFP}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--pinentry-mode", "loopback", "--homedir", home, "--passphrase", KnownPassphrase, "--output", protectedSecretPath, "--armor", "--export-secret-keys", protectedFP}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--homedir", home, "--output", plainSecretPath, "--armor", "--export-secret-keys", plainFP}, env, ""); err != nil {
		return err
	}
	if err := runner.Run(ctx, "gpg", []string{"--batch", "--yes", "--pinentry-mode", "loopback", "--homedir", home, "--passphrase", KnownPassphrase, "--local-user", protectedFP, "--output", signaturePath, "--armor", "--detach-sign", filepath.Join(root, "sample.txt")}, env, ""); err != nil {
		return err
	}
	if err := copyFirstRevocation(filepath.Join(home, "openpgp-revocs.d"), revocationPath); err != nil {
		return err
	}

	if err := chmodFile(publicPath, guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(protectedSecretPath, guardrail.SecretPerm); err != nil {
		return err
	}
	if err := chmodFile(plainSecretPath, guardrail.SecretPerm); err != nil {
		return err
	}
	if err := chmodFile(signaturePath, guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(revocationPath, guardrail.PublicPerm); err != nil {
		return err
	}

	// Class public-bundle: machine-readable multi-key public export (not a
	// 1:1 twin of private-protected). Single-key publics would use "public".
	appendArtifact(manifest, "gpg", "public-bundle", rel(root, publicPath))
	appendArtifact(manifest, "gpg", "private-protected", rel(root, protectedSecretPath))
	appendArtifact(manifest, "gpg", "private-plain", rel(root, plainSecretPath))
	appendArtifact(manifest, "gpg", "signature", rel(root, signaturePath))
	appendArtifact(manifest, "gpg", "revocation", rel(root, revocationPath))
	return nil
}

// keyFingerprint maps a UID email (exact) to a primary fingerprint.
type keyFingerprint struct {
	Email       string
	Fingerprint string
}

func listSecretKeyFingerprints(ctx context.Context, root string, runner Runner) ([]keyFingerprint, error) {
	home := filepath.Join(root, ".gnupg")
	out, err := runner.Output(ctx, "gpg", []string{"--batch", "--homedir", home, "--with-colons", "--list-secret-keys"}, sidecarEnv(root), "")
	if err != nil {
		return nil, fmt.Errorf("list gpg secret key fingerprints: %w", err)
	}
	return parseColonFingerprints(out)
}

// parseColonFingerprints walks GnuPG --with-colons secret-key listing.
// For each primary secret key, the next fpr line is the primary fingerprint;
// uid lines supply email addresses associated with that key.
func parseColonFingerprints(out string) ([]keyFingerprint, error) {
	var result []keyFingerprint
	var currentFP string
	var emails []string

	flush := func() {
		if currentFP == "" {
			return
		}
		for _, email := range emails {
			result = append(result, keyFingerprint{Email: email, Fingerprint: currentFP})
		}
		currentFP = ""
		emails = nil
	}

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "sec", "sec+":
			flush()
		case "fpr", "fp2":
			// Primary fingerprint is the first fpr after sec; ignore subkey fpr
			// once we already have a current FP and have started seeing uids...
			// Actually order is: sec, fpr (primary), grp?, uid, ssb, fpr (sub)...
			// Take first fpr after sec only.
			if currentFP == "" && len(fields) > 9 {
				fp := strings.TrimSpace(fields[9])
				if fp != "" {
					currentFP = strings.ToUpper(fp)
				}
			}
		case "uid":
			if len(fields) > 9 {
				if email := emailFromUID(fields[9]); email != "" {
					emails = append(emails, email)
				}
			}
		}
	}
	flush()

	if len(result) == 0 {
		return nil, fmt.Errorf("no gpg secret key fingerprints parsed from --with-colons listing")
	}
	return result, nil
}

func emailFromUID(uid string) string {
	// UID forms: "Name (comment) <email@host>" or bare email
	start := strings.LastIndex(uid, "<")
	end := strings.LastIndex(uid, ">")
	if start >= 0 && end > start {
		return strings.TrimSpace(uid[start+1 : end])
	}
	if strings.Contains(uid, "@") {
		return strings.TrimSpace(uid)
	}
	return ""
}

func fingerprintForEmail(keys []keyFingerprint, email string) (string, error) {
	var matches []string
	for _, k := range keys {
		if strings.EqualFold(k.Email, email) {
			matches = append(matches, k.Fingerprint)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no secret key fingerprint for exact email %q", email)
	case 1:
		return matches[0], nil
	default:
		// Same email on multiple keys is unexpected; fail closed rather than pick.
		return "", fmt.Errorf("multiple secret key fingerprints for exact email %q", email)
	}
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
