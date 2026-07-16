package generator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/3leaps/synthcorpus/internal/guardrail"
)

func generateMinisign(ctx context.Context, root string, runner Runner, manifest *Manifest) error {
	dir := filepath.Join(root, "minisign")
	protectedPub := filepath.Join(dir, "minisign-protected.pub")
	protectedSecret := filepath.Join(dir, "minisign-protected.key")
	plainPub := filepath.Join(dir, "minisign-plain.pub")
	plainSecret := filepath.Join(dir, "minisign-plain.key")
	sig := filepath.Join(dir, "sample.txt.minisig")

	if err := runner.Run(ctx, "minisign", []string{"-G", "-p", protectedPub, "-s", protectedSecret}, sidecarEnv(root), KnownPassphrase+"\n"+KnownPassphrase+"\n"); err != nil {
		return err
	}
	if err := stampMinisignComment(protectedPub, "public protected"); err != nil {
		return err
	}
	if err := stampMinisignComment(protectedSecret, "secret protected"); err != nil {
		return err
	}
	if err := runner.Run(ctx, "minisign", []string{"-G", "-W", "-p", plainPub, "-s", plainSecret}, sidecarEnv(root), ""); err != nil {
		return err
	}
	if err := stampMinisignComment(plainPub, "public plain"); err != nil {
		return err
	}
	if err := stampMinisignComment(plainSecret, "secret plain"); err != nil {
		return err
	}
	if err := runner.Run(ctx, "minisign", []string{"-S", "-x", sig, "-s", protectedSecret, "-c", "synthcorpus generated-real TEST KEY - DO NOT USE", "-t", "synthcorpus generated-real test signature", "-m", filepath.Join(root, "sample.txt")}, sidecarEnv(root), KnownPassphrase+"\n"); err != nil {
		return err
	}

	appendArtifact(manifest, "minisign", "public", rel(root, protectedPub))
	appendArtifact(manifest, "minisign", "private-protected", rel(root, protectedSecret))
	appendArtifact(manifest, "minisign", "public", rel(root, plainPub))
	appendArtifact(manifest, "minisign", "private-plain", rel(root, plainSecret))
	appendArtifact(manifest, "minisign", "signature", rel(root, sig))

	if err := chmodFile(protectedPub, guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(plainPub, guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(sig, guardrail.PublicPerm); err != nil {
		return err
	}
	if err := chmodFile(protectedSecret, guardrail.SecretPerm); err != nil {
		return err
	}
	if err := chmodFile(plainSecret, guardrail.SecretPerm); err != nil {
		return err
	}
	return nil
}

func stampMinisignComment(path, label string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read minisign artifact for comment stamping: %w", err)
	}
	text := string(data)
	_, rest, ok := strings.Cut(text, "\n")
	if !ok {
		return fmt.Errorf("minisign artifact has no comment line: %s", path)
	}
	comment := "untrusted comment: synthcorpus generated-real TEST KEY - DO NOT USE (" + label + ")"
	// Stamped secrets stay 0600; public files get corrected by generateMinisign chmod.
	return os.WriteFile(path, []byte(comment+"\n"+rest), guardrail.SecretPerm)
}
