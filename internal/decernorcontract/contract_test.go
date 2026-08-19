package decernorcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommittedManifestsAreStrictAndSelfConsistent(t *testing.T) {
	root := repoRoot(t)
	golden, err := LoadGoldenManifest(filepath.Join(root, GoldenManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	if golden.ExpectedRecords != 10 {
		t.Fatalf("expected_records=%d", golden.ExpectedRecords)
	}
	properties, err := LoadGeneratedProperties(filepath.Join(root, GeneratedPropertiesPath))
	if err != nil {
		t.Fatal(err)
	}
	if properties.ExpectedRecordCount != 21 {
		t.Fatalf("expected_record_count=%d", properties.ExpectedRecordCount)
	}
}

func TestParseNDJSONRejectsSchemaDrift(t *testing.T) {
	validNull := `{"schema_version":"v0","path":"ssh/id","kind":"ssh","class":"private","algorithm":"sha256","fingerprint":null,"fingerprint_scheme":"ssh-rfc4253-public-blob-sha256-v1","confidence":"medium","reason":"parse-unsupported"}` + "\n"
	validPositive := `{"schema_version":"v0","path":"ssh/id.pub","kind":"ssh","class":"public","algorithm":"sha256","fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","fingerprint_scheme":"ssh-rfc4253-public-blob-sha256-v1","confidence":"high"}` + "\n"
	if _, err := ParseNDJSON([]byte(validNull)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseNDJSON([]byte(validPositive)); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"unknown-field":       strings.Replace(validNull, `"confidence":"medium"`, `"confidence":"medium","generated":"now"`, 1),
		"missing-path":        strings.Replace(validNull, `"path":"ssh/id",`, "", 1),
		"unknown-kind":        strings.Replace(validNull, `"kind":"ssh"`, `"kind":"future"`, 1),
		"unknown-class":       strings.Replace(validNull, `"class":"private"`, `"class":"opaque"`, 1),
		"unknown-algorithm":   strings.Replace(validNull, `"algorithm":"sha256"`, `"algorithm":"md5"`, 1),
		"unknown-scheme":      strings.Replace(validNull, `"fingerprint_scheme":"ssh-rfc4253-public-blob-sha256-v1"`, `"fingerprint_scheme":"future-v1"`, 1),
		"unknown-confidence":  strings.Replace(validNull, `"confidence":"medium"`, `"confidence":"certain"`, 1),
		"unknown-reason":      strings.Replace(validNull, `"reason":"parse-unsupported"`, `"reason":"filtered"`, 1),
		"missing-null-reason": strings.Replace(validNull, `,"reason":"parse-unsupported"`, "", 1),
		"empty-key-id":        strings.Replace(validPositive, `"confidence":"high"`, `"key_id":"","confidence":"high"`, 1),
		"empty-reason":        strings.Replace(validPositive, `"confidence":"high"`, `"confidence":"high","reason":""`, 1),
		"null-key-id":         strings.Replace(validPositive, `"confidence":"high"`, `"key_id":null,"confidence":"high"`, 1),
		"null-reason":         strings.Replace(validPositive, `"confidence":"high"`, `"confidence":"high","reason":null`, 1),
		"empty-fingerprint":   strings.Replace(validPositive, `"fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"fingerprint":""`, 1),
		"key-role-on-ssh":     strings.Replace(validPositive, `"confidence":"high"`, `"key_role":"primary","confidence":"high"`, 1),
		"not-terminated":      strings.TrimSuffix(validNull, "\n"),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNDJSON([]byte(input)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestCheckStableOrderingRejectsReorderedRecords(t *testing.T) {
	records := []Record{
		{Path: "b", Kind: "ssh", Class: "public", FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Reason: stringPointer("parse-unsupported")},
		{Path: "a", Kind: "ssh", Class: "public", FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Reason: stringPointer("parse-unsupported")},
	}
	if err := CheckStableOrdering(records); err == nil {
		t.Fatal("expected ordering rejection")
	}
}

func TestValidateGeneratedRecordsRejectsIncompatibleTuples(t *testing.T) {
	canonical := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tests := map[string]Record{
		"minisign-with-ssh-scheme": {
			SchemaVersion: recordSchemaVersion, Path: "minisign/key.pub", Kind: "minisign", Class: "public", Algorithm: "sha256",
			Fingerprint: &canonical, FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Confidence: "high",
		},
		"ssh-scheme-wrong-algorithm": {
			SchemaVersion: recordSchemaVersion, Path: "ssh/key.pub", Kind: "ssh", Class: "public", Algorithm: "minisign-key-id",
			Fingerprint: &canonical, FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Confidence: "high",
		},
		"null-record-invalid-tuple": {
			SchemaVersion: recordSchemaVersion, Path: "minisign/key", Kind: "minisign", Class: "private", Algorithm: "sha256",
			FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Confidence: "medium", Reason: stringPointer("parse-unsupported"),
		},
	}
	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			properties := GeneratedProperties{
				ExpectedRecordCount: 1,
				SchemeCounts:        map[string]int{record.FingerprintScheme: 1},
				ClosedReasons:       []string{"parse-unsupported"},
			}
			if err := ValidateGeneratedRecords([]Record{record}, properties); err == nil {
				t.Fatal("expected incompatible tuple rejection")
			}
		})
	}
}

func TestGoldenComparisonFailsOnConsumerDrift(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadGoldenManifest(filepath.Join(root, GoldenManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifest.Golden.Path)))
	if err != nil {
		t.Fatal(err)
	}
	if err := compareGolden(golden, golden, manifest); err != nil {
		t.Fatal(err)
	}
	drifted := bytes.Replace(golden, []byte(`"confidence":"high"`), []byte(`"confidence":"medium"`), 1)
	if bytes.Equal(drifted, golden) {
		t.Fatal("drift mutation did not apply")
	}
	if err := compareGolden(drifted, golden, manifest); err == nil || !strings.Contains(err.Error(), "fingerprint drift") {
		t.Fatalf("expected fingerprint drift error, got %v", err)
	}
}

func TestGoldenComparisonRejectsInvalidRelativePaths(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadGoldenManifest(filepath.Join(root, GoldenManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifest.Golden.Path)))
	if err != nil {
		t.Fatal(err)
	}
	old := []byte(`"path":"gpg/private.asc"`)
	tests := map[string]string{
		"absolute":               `/tmp/private.asc`,
		"windows-absolute":       `C:/temp/private.asc`,
		"windows-drive-relative": `c:temp/private.asc`,
		"parent":                 `../private.asc`,
		"backslash":              `gpg\\private.asc`,
		"non-canonical":          `gpg/./private.asc`,
	}
	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			replacement := []byte(fmt.Sprintf(`"path":"%s"`, path))
			mutated := bytes.Replace(golden, old, replacement, 1)
			if bytes.Equal(mutated, golden) {
				t.Fatal("path mutation did not apply")
			}
			changedManifest := manifest
			changedManifest.Golden.SHA256 = digest(mutated)
			if err := compareGolden(mutated, mutated, changedManifest); err == nil || !strings.Contains(err.Error(), "golden paths") {
				t.Fatalf("expected golden path rejection, got %v", err)
			}
		})
	}
	invalidActual := bytes.Replace(golden, old, []byte(`"path":"/tmp/private.asc"`), 1)
	if err := compareGolden(invalidActual, golden, manifest); err == nil || !strings.Contains(err.Error(), "decernor paths") {
		t.Fatalf("expected actual output path rejection, got %v", err)
	}
}

func TestParseNDJSONGPGSuccessRequiresRole(t *testing.T) {
	fp := strings.Repeat("AB", 20)
	keyID := fp[len(fp)-16:]
	valid := `{"schema_version":"v0","path":"gpg/public.asc","kind":"gpg","class":"public","algorithm":"openpgp-fingerprint","fingerprint":"` + fp + `","fingerprint_scheme":"openpgp-fingerprint-v1","key_id":"` + keyID + `","key_role":"primary","confidence":"high"}` + "\n"
	if _, err := ParseNDJSON([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	missingRole := strings.Replace(valid, `,"key_role":"primary"`, "", 1)
	if _, err := ParseNDJSON([]byte(missingRole)); err == nil {
		t.Fatal("expected missing key_role rejection")
	}
	nullGPG := `{"schema_version":"v0","path":"gpg/public.asc","kind":"gpg","class":"public","algorithm":"openpgp-fingerprint","fingerprint":null,"fingerprint_scheme":"openpgp-fingerprint-v1","key_role":"primary","confidence":"medium","reason":"parse-unsupported"}` + "\n"
	if _, err := ParseNDJSON([]byte(nullGPG)); err == nil {
		t.Fatal("expected key_role on null gpg rejection")
	}
}

func TestCanonicalFingerprintEncodings(t *testing.T) {
	canonicalSHA := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, sha256.Size))
	canonicalMinisignBlob := strings.Repeat("ab", 32)
	canonicalOpenPGP20 := strings.Repeat("AB", 20)
	canonicalOpenPGP32 := strings.Repeat("CD", 32)
	tests := []struct {
		name    string
		scheme  string
		value   string
		keyID   *string
		wantErr bool
	}{
		{name: "sha-32-byte", scheme: "ssh-rfc4253-public-blob-sha256-v1", value: canonicalSHA},
		{name: "sha-invalid-pad-bits", scheme: "ssh-rfc4253-public-blob-sha256-v1", value: "SHA256:" + strings.Repeat("A", 42) + "B", wantErr: true},
		{name: "minisign-blob-hex", scheme: "minisign-public-blob-sha256-v1", value: canonicalMinisignBlob},
		{name: "minisign-blob-old-sha256", scheme: "minisign-public-blob-sha256-v1", value: "SHA256:not+base64!", wantErr: true},
		{name: "minisign-blob-uppercase", scheme: "minisign-public-blob-sha256-v1", value: strings.Repeat("AB", 32), wantErr: true},
		{name: "sha-wrong-decoded-length", scheme: "ssh-rfc4253-public-blob-sha256-v1", value: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 31)), wantErr: true},
		{name: "openpgp-v4-20-byte", scheme: "openpgp-fingerprint-v1", value: canonicalOpenPGP20},
		{name: "openpgp-v5-32-byte", scheme: "openpgp-fingerprint-v1", value: canonicalOpenPGP32},
		{name: "openpgp-odd-hex", scheme: "openpgp-fingerprint-v1", value: strings.Repeat("A", 33), wantErr: true},
		{name: "openpgp-unsupported-length", scheme: "openpgp-fingerprint-v1", value: strings.Repeat("AB", 18), wantErr: true},
		{name: "openpgp-lowercase", scheme: "openpgp-fingerprint-v1", value: strings.Repeat("ab", 20), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record := Record{Fingerprint: &tc.value, FingerprintScheme: tc.scheme, KeyID: tc.keyID}
			err := validateFingerprintEncoding(record)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateGeneratedRecordsRejectsPathAndEncodingLeaks(t *testing.T) {
	properties := GeneratedProperties{
		ExpectedRecordCount: 1,
		SchemeCounts:        map[string]int{"ssh-rfc4253-public-blob-sha256-v1": 1},
		ClosedReasons:       []string{"parse-unsupported"},
	}
	fingerprint := "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	record := Record{
		SchemaVersion: recordSchemaVersion, Path: "ssh/id.pub", Kind: "ssh", Class: "public",
		Algorithm: "sha256", Fingerprint: &fingerprint,
		FingerprintScheme: "ssh-rfc4253-public-blob-sha256-v1", Confidence: "high",
	}
	if err := ValidateGeneratedRecords([]Record{record}, properties); err != nil {
		t.Fatal(err)
	}

	badPaths := []string{"/tmp/key.pub", "C:/temp/key.pub", "d:temp/key.pub"}
	for _, path := range badPaths {
		badPath := record
		badPath.Path = path
		if err := ValidateGeneratedRecords([]Record{badPath}, properties); err == nil {
			t.Fatal("expected non-relative path rejection")
		}
	}
	badFingerprint := record
	value := "SHA256:" + strings.Repeat("A", 42) + "B"
	badFingerprint.Fingerprint = &value
	err := ValidateGeneratedRecords([]Record{badFingerprint}, properties)
	if err == nil {
		t.Fatal("expected padded fingerprint rejection")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatal("validation error persisted generated-real fingerprint value")
	}
}

func stringPointer(value string) *string {
	return &value
}

func TestLoadManifestRejectsUnknownField(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, GoldenManifestPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["generated"] = "forbidden"
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(temp, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGoldenManifest(temp); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
