package provability

import "testing"

func TestColonKeyringHasKeys(t *testing.T) {
	empty := "tru::1:123:0:3:1:5\n"
	if colonKeyringHasKeys(empty) {
		t.Fatal("empty trustdb-only output must not count as keys")
	}
	populated := "pub:-:255:22:AABB:0:0:0:::\nfpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
	if !colonKeyringHasKeys(populated) {
		t.Fatal("expected pub/fpr detection")
	}
	secret := "sec:-:255:22:AABB:0:0:0:::\nssb:-:255:22:CCDD:0:0:0:::\n"
	if !colonKeyringHasKeys(secret) {
		t.Fatal("expected sec/ssb detection")
	}
}
