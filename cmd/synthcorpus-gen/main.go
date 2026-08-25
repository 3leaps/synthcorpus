package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/3leaps/synthcorpus"
	"github.com/3leaps/synthcorpus/internal/generator"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "synthcorpus-gen: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("synthcorpus-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var out string
	var force bool
	var showVersion bool
	fs.StringVar(&out, "out", "", "output directory outside any git worktree; empty uses $SYNTHCORPUS_OUT/<tool> or a local isolated root")
	fs.BoolVar(&force, "force", false, "replace an existing synthcorpus-owned generated-real directory")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Fprintln(stdout, synthcorpus.Version())
		return nil
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: synthcorpus-gen [--out DIR] [--force] <tool>")
	}

	tool := fs.Arg(0)
	if out == "" {
		if root := strings.TrimSpace(os.Getenv("SYNTHCORPUS_OUT")); root != "" {
			out = filepath.Join(root, tool)
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("resolve home directory: %w", err)
			}
			out = filepath.Join(home, "dev", "dogfooding", tool)
		}
	}

	return generator.Generate(context.Background(), generator.Options{
		Tool:  tool,
		Out:   out,
		Force: force,
	})
}
