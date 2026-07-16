package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/3leaps/synthcorpus/internal/generator"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "synthcorpus-gen: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("synthcorpus-gen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var out string
	var force bool
	fs.StringVar(&out, "out", "", "output directory; defaults to ~/dev/dogfooding/<tool>")
	fs.BoolVar(&force, "force", false, "replace an existing synthcorpus-owned generated-real directory")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: synthcorpus-gen [--out DIR] [--force] <tool>")
	}

	tool := fs.Arg(0)
	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		out = filepath.Join(home, "dev", "dogfooding", tool)
	}

	return generator.Generate(context.Background(), generator.Options{
		Tool:  tool,
		Out:   out,
		Force: force,
	})
}
