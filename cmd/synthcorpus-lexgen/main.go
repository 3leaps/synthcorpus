package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/3leaps/synthcorpus"
	"github.com/3leaps/synthcorpus/internal/lexmatrix"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "synthcorpus-lexgen: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("synthcorpus-lexgen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var out string
	var seed uint
	var profile string
	var force bool
	var includeExtensions bool
	var showVersion bool

	fs.StringVar(&out, "out", "", "output directory; defaults to ~/dev/dogfooding/lexmatrix")
	fs.UintVar(&seed, "seed", 0, "generation seed (0-4294967295)")
	fs.StringVar(&profile, "profile", "seed", "corpus profile label recorded in the fixture set; does not change generation")
	fs.BoolVar(&force, "force", false, "replace an existing synthcorpus-owned output directory")
	fs.BoolVar(&includeExtensions, "include-extensions", false, "add implemented cells outside the required matrix")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if showVersion {
		fmt.Fprintln(stdout, synthcorpus.Version())
		return nil
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: synthcorpus-lexgen [--out DIR] [--seed N] [--profile P] [--force] [--include-extensions]")
	}
	if seed > 4294967295 {
		return fmt.Errorf("seed %d exceeds the 32-bit range the fixture contract allows", seed)
	}
	switch profile {
	case "seed", "changed_set", "full_tree":
	default:
		return fmt.Errorf("unknown profile %q: want seed, changed_set, or full_tree", profile)
	}

	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		out = filepath.Join(home, "dev", "dogfooding", "lexmatrix")
	}

	result, err := lexmatrix.Generate(lexmatrix.Options{
		Seed:              uint32(seed),
		Profile:           profile,
		IncludeExtensions: includeExtensions,
	})
	if err != nil {
		return err
	}

	written, err := lexmatrix.Write(out, result, force)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "root:             %s\n", written.Root)
	fmt.Fprintf(stdout, "cases:            %d\n", written.CaseCount)
	fmt.Fprintf(stdout, "terms:            %d\n", written.TermCount)
	fmt.Fprintf(stdout, "sources:          %d\n", written.SourceCount)
	fmt.Fprintf(stdout, "candidates:       %d\n", written.CandidateCount)
	fmt.Fprintf(stdout, "fixtures sha256:  %s\n", written.FixtureSHA256)
	fmt.Fprintf(stdout, "manifest sha256:  %s\n", written.ManifestSHA256)
	return nil
}
