package provability

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

type stubRunner struct {
	out []byte
	err error
}

func (s stubRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return s.out, s.err
}

func TestValidateGPGCapability(t *testing.T) {
	if err := ValidateGPGCapability([]byte("gpg (GnuPG) 2.4.9\n"), nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGPGCapability([]byte("not-gpg"), nil); err == nil {
		t.Fatal("expected identity failure")
	}
	if err := ValidateGPGCapability([]byte("gpg (GnuPG)"), errors.New("exit 1")); err == nil {
		t.Fatal("expected error on nonzero")
	}
	// exit-only shim
	if err := ValidateGPGCapability(nil, &exec.ExitError{}); err == nil {
		t.Fatal("expected failure for exit-only")
	}
}

func TestValidateMinisignCapability(t *testing.T) {
	if err := ValidateMinisignCapability([]byte("minisign 0.12\n"), nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMinisignCapability([]byte("nope"), nil); err == nil {
		t.Fatal("expected identity failure")
	}
}

func TestValidateSSHKeygenCapability(t *testing.T) {
	errExit := &exec.ExitError{}
	if err := ValidateSSHKeygenCapability([]byte("unknown key type __x__\n"), errExit); err != nil {
		t.Fatal(err)
	}
	// startable exit 1 with no diagnostic — false green before this fix
	if err := ValidateSSHKeygenCapability(nil, errExit); err == nil {
		t.Fatal("expected diagnostic failure for empty shim output")
	}
	if err := ValidateSSHKeygenCapability([]byte("unknown key type"), nil); err == nil {
		t.Fatal("expected nonzero exit")
	}
}

func TestProbeRejectsExitOnlyShims(t *testing.T) {
	ctx := context.Background()
	shim := stubRunner{out: nil, err: &exec.ExitError{}}
	if err := probeGPG(ctx, shim, "gpg"); err == nil {
		t.Fatal("gpg must reject exit-only shim")
	}
	if err := probeMinisign(ctx, shim, "minisign"); err == nil {
		t.Fatal("minisign must reject exit-only shim")
	}
	if err := probeSSHKeygen(ctx, shim, "ssh-keygen"); err == nil {
		t.Fatal("ssh-keygen must reject exit-only shim")
	}
}
