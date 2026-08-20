// Package decernorcontract verifies synthcorpus's binary-only consumer
// contract with a pinned decernor build.
package decernorcontract

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/3leaps/synthcorpus/internal/decernorloc"
	"github.com/3leaps/synthcorpus/internal/guardrail"
)

const (
	GoldenManifestPath      = "manifests/decernor-fingerprint-golden.json"
	GeneratedPropertiesPath = "manifests/decernor-generated-real-properties.json"
	PinPath                 = "manifests/decernor-pin.json"
	recordSchemaVersion     = "v0"
	goldenManifestKind      = "synthcorpus-decernor-fingerprint-golden"
	generatedManifestKind   = "synthcorpus-decernor-generated-real-properties"
)

var validKinds = map[string]bool{"gpg": true, "ssh": true, "minisign": true}

var validClasses = map[string]bool{"public": true, "private": true, "other": true}

var validAlgorithms = map[string]bool{
	"openpgp-fingerprint": true,
	"sha256":              true,
	"minisign-key-id":     true,
}

var validSchemes = map[string]bool{
	"openpgp-fingerprint-v1":            true,
	"ssh-rfc4253-public-blob-sha256-v1": true,
	"minisign-key-id-v1":                true,
	"minisign-public-blob-sha256-v1":    true,
}

var validConfidence = map[string]bool{"high": true, "medium": true, "low": true}

var validReasons = map[string]bool{
	"encrypted-private-no-public-counterpart": true,
	"helper-unavailable":                      true,
	"parse-unsupported":                       true,
	"too-large":                               true,
	"unreadable":                              true,
	"unsupported-kind":                        true,
	"unsupported-version":                     true,
}

// Invocation is the deterministic decernor command surface declared by a
// contract manifest. Input is resolved below the synthcorpus repo root.
type Invocation struct {
	Command     string `json:"command"`
	Input       string `json:"input"`
	Format      string `json:"format"`
	PathMode    string `json:"path_mode"`
	FailOnEmpty bool   `json:"fail_on_empty"`
}

// Normalization declares the output stability rules. The verifier does not
// transform output: these fields document and enforce the raw byte contract.
type Normalization struct {
	PathSeparator string   `json:"path_separator"`
	Ordering      []string `json:"ordering"`
	Timestamps    string   `json:"timestamps"`
}

type GoldenFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type GoldenManifest struct {
	SchemaVersion   string        `json:"schema_version"`
	Kind            string        `json:"kind"`
	MaterialLane    string        `json:"material_lane"`
	PinReference    string        `json:"pin_reference"`
	Invocation      Invocation    `json:"invocation"`
	Normalization   Normalization `json:"normalization"`
	ExpectedRecords int           `json:"expected_records"`
	Golden          GoldenFile    `json:"golden"`
}

type PathPolicy struct {
	Mode            string `json:"mode"`
	Separator       string `json:"separator"`
	AbsolutePaths   string `json:"absolute_paths"`
	ParentTraversal string `json:"parent_traversal"`
}

type RecordSelector struct {
	Path              string `json:"path"`
	Kind              string `json:"kind"`
	Class             string `json:"class"`
	FingerprintScheme string `json:"fingerprint_scheme"`
	Reason            string `json:"reason"`
}

type RequiredPathSchemes struct {
	Path    string   `json:"path"`
	Schemes []string `json:"schemes"`
}

type GeneratedProperties struct {
	SchemaVersion       string                `json:"schema_version"`
	Kind                string                `json:"kind"`
	MaterialLane        string                `json:"material_lane"`
	PinReference        string                `json:"pin_reference"`
	Invocation          Invocation            `json:"invocation"`
	ExpectedRecordCount int                   `json:"expected_record_count"`
	SchemeCounts        map[string]int        `json:"scheme_counts"`
	ClosedReasons       []string              `json:"closed_reasons"`
	RequiredNullRecords []RecordSelector      `json:"required_null_records"`
	RequiredPathSchemes []RequiredPathSchemes `json:"required_path_schemes"`
	PathPolicy          PathPolicy            `json:"path_policy"`
}

// Record mirrors the public decernor fingerprint v0 NDJSON schema. Unknown
// fields and absent required fields are rejected before this type is decoded.
type Record struct {
	SchemaVersion     string  `json:"schema_version"`
	Path              string  `json:"path"`
	Kind              string  `json:"kind"`
	Class             string  `json:"class"`
	Algorithm         string  `json:"algorithm"`
	Fingerprint       *string `json:"fingerprint"`
	FingerprintScheme string  `json:"fingerprint_scheme"`
	KeyID             *string `json:"key_id,omitempty"`
	KeyRole           *string `json:"key_role,omitempty"`
	Confidence        string  `json:"confidence"`
	Reason            *string `json:"reason,omitempty"`
}

func LoadGoldenManifest(path string) (GoldenManifest, error) {
	var manifest GoldenManifest
	if err := loadStrictJSON(path, &manifest); err != nil {
		return GoldenManifest{}, err
	}
	if err := validateGoldenManifest(manifest); err != nil {
		return GoldenManifest{}, err
	}
	return manifest, nil
}

func LoadGeneratedProperties(path string) (GeneratedProperties, error) {
	var properties GeneratedProperties
	if err := loadStrictJSON(path, &properties); err != nil {
		return GeneratedProperties{}, err
	}
	if err := validateGeneratedProperties(properties); err != nil {
		return GeneratedProperties{}, err
	}
	return properties, nil
}

func loadStrictJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

func validateGoldenManifest(m GoldenManifest) error {
	if m.SchemaVersion != recordSchemaVersion || m.Kind != goldenManifestKind {
		return fmt.Errorf("unsupported golden manifest identity %q/%q", m.SchemaVersion, m.Kind)
	}
	if m.MaterialLane != "committed-synthetic" {
		return fmt.Errorf("golden material_lane %q", m.MaterialLane)
	}
	if m.PinReference != PinPath {
		return fmt.Errorf("golden pin_reference %q", m.PinReference)
	}
	if err := validateInvocation(m.Invocation, "fixtures"); err != nil {
		return err
	}
	if err := validateNormalization(m.Normalization); err != nil {
		return err
	}
	if m.ExpectedRecords <= 0 {
		return errors.New("golden expected_records must be positive")
	}
	if !cleanRepoRelative(m.Golden.Path) || !strings.HasPrefix(m.Golden.Path, "manifests/") {
		return fmt.Errorf("unsafe golden path %q", m.Golden.Path)
	}
	if len(m.Golden.SHA256) != sha256.Size*2 {
		return errors.New("golden sha256 must be 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(m.Golden.SHA256); err != nil || strings.ToLower(m.Golden.SHA256) != m.Golden.SHA256 {
		return errors.New("golden sha256 must be 64 lowercase hex characters")
	}
	return nil
}

func validateGeneratedProperties(p GeneratedProperties) error {
	if p.SchemaVersion != recordSchemaVersion || p.Kind != generatedManifestKind {
		return fmt.Errorf("unsupported generated-real manifest identity %q/%q", p.SchemaVersion, p.Kind)
	}
	if p.MaterialLane != "generated-real" || p.PinReference != PinPath {
		return errors.New("generated-real manifest lane or pin reference is invalid")
	}
	if err := validateInvocation(p.Invocation, "generated-real-root"); err != nil {
		return err
	}
	if p.ExpectedRecordCount <= 0 || len(p.SchemeCounts) == 0 {
		return errors.New("generated-real record and scheme counts are required")
	}
	total := 0
	for scheme, count := range p.SchemeCounts {
		if scheme == "" || count <= 0 {
			return errors.New("generated-real scheme counts must be positive")
		}
		total += count
	}
	if total != p.ExpectedRecordCount {
		return fmt.Errorf("scheme count total %d does not equal expected record count %d", total, p.ExpectedRecordCount)
	}
	if len(p.ClosedReasons) == 0 || len(p.RequiredNullRecords) == 0 || len(p.RequiredPathSchemes) == 0 {
		return errors.New("generated-real closed reasons and required record properties are required")
	}
	if p.PathPolicy != (PathPolicy{Mode: "relative", Separator: "/", AbsolutePaths: "forbidden", ParentTraversal: "forbidden"}) {
		return fmt.Errorf("unsupported generated-real path policy %#v", p.PathPolicy)
	}
	return nil
}

func validateInvocation(i Invocation, input string) error {
	if i.Command != "fingerprint" || i.Input != input || i.Format != "ndjson" || i.PathMode != "relative" || !i.FailOnEmpty {
		return fmt.Errorf("unsupported deterministic invocation %#v", i)
	}
	return nil
}

func validateNormalization(n Normalization) error {
	want := []string{"path", "kind", "class", "fingerprint_scheme", "key_role", "key_id|fingerprint|reason"}
	if n.PathSeparator != "/" || n.Timestamps != "absent" || !equalStrings(n.Ordering, want) {
		return fmt.Errorf("unsupported normalization %#v", n)
	}
	return nil
}

func cleanRepoRelative(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.VolumeName(path) != "" || strings.Contains(path, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	return clean == path && clean != ".." && !strings.HasPrefix(clean, "../")
}

// ResolvePinnedBinary locates decernor by explicit absolute path, DECERNOR_BIN,
// or PATH and then enforces the repository pin.
func ResolvePinnedBinary(ctx context.Context, repoRoot, explicit string) (string, error) {
	pin, err := decernorloc.LoadPin(filepath.Join(repoRoot, PinPath))
	if err != nil {
		return "", err
	}
	binary, err := decernorloc.LocateBinary(explicit, pin)
	if err != nil {
		return "", err
	}
	id, err := decernorloc.ReadIdentity(ctx, binary)
	if err != nil {
		return "", err
	}
	if err := decernorloc.CheckPin(id, pin); err != nil {
		return "", err
	}
	return binary, nil
}

// CheckCommittedSynthetic compares raw decernor NDJSON bytes with the pinned
// committed golden. No normalization or field stripping occurs at runtime.
func CheckCommittedSynthetic(ctx context.Context, repoRoot, explicitBinary string) error {
	manifest, err := LoadGoldenManifest(filepath.Join(repoRoot, GoldenManifestPath))
	if err != nil {
		return err
	}
	binary, err := ResolvePinnedBinary(ctx, repoRoot, explicitBinary)
	if err != nil {
		return err
	}
	goldenPath := filepath.Join(repoRoot, filepath.FromSlash(manifest.Golden.Path))
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		return fmt.Errorf("read golden output: %w", err)
	}
	actual, err := runFingerprint(ctx, binary, filepath.Join(repoRoot, "fixtures"), manifest.Invocation)
	if err != nil {
		return err
	}
	return compareGolden(actual, golden, manifest)
}

func compareGolden(actual, golden []byte, manifest GoldenManifest) error {
	if got := digest(golden); got != manifest.Golden.SHA256 {
		return fmt.Errorf("golden digest %s does not match manifest %s", got, manifest.Golden.SHA256)
	}
	goldenRecords, err := ParseNDJSON(golden)
	if err != nil {
		return fmt.Errorf("parse committed golden: %w", err)
	}
	if len(goldenRecords) != manifest.ExpectedRecords {
		return fmt.Errorf("golden record count %d, want %d", len(goldenRecords), manifest.ExpectedRecords)
	}
	if err := validateRecordPaths(goldenRecords); err != nil {
		return fmt.Errorf("golden paths: %w", err)
	}
	if err := CheckStableOrdering(goldenRecords); err != nil {
		return fmt.Errorf("golden ordering: %w", err)
	}
	actualRecords, err := ParseNDJSON(actual)
	if err != nil {
		return fmt.Errorf("parse decernor output: %w", err)
	}
	if err := validateRecordPaths(actualRecords); err != nil {
		return fmt.Errorf("decernor paths: %w", err)
	}
	if err := CheckStableOrdering(actualRecords); err != nil {
		return fmt.Errorf("decernor ordering: %w", err)
	}
	if !bytes.Equal(actual, golden) {
		return fmt.Errorf("decernor fingerprint drift: actual sha256 %s, golden sha256 %s", digest(actual), manifest.Golden.SHA256)
	}
	return nil
}

// CheckGeneratedReal validates only declared properties. It never returns,
// writes, or persists the generated corpus's random fingerprints.
func CheckGeneratedReal(ctx context.Context, repoRoot, corpusRoot, explicitBinary string) error {
	properties, err := LoadGeneratedProperties(filepath.Join(repoRoot, GeneratedPropertiesPath))
	if err != nil {
		return err
	}
	canonicalRoot, err := guardrail.ResolveOutputPath(corpusRoot)
	if err != nil {
		return fmt.Errorf("resolve generated-real root: %w", err)
	}
	if err := ensureOutsideRepo(repoRoot, canonicalRoot); err != nil {
		return err
	}
	if err := guardrail.CheckOwnedMarker(canonicalRoot); err != nil {
		return fmt.Errorf("generated-real root ownership: %w", err)
	}
	binary, err := ResolvePinnedBinary(ctx, repoRoot, explicitBinary)
	if err != nil {
		return err
	}
	output, err := runFingerprint(ctx, binary, canonicalRoot, properties.Invocation)
	if err != nil {
		return err
	}
	records, err := ParseNDJSON(output)
	if err != nil {
		return err
	}
	return ValidateGeneratedRecords(records, properties)
}

func ensureOutsideRepo(repoRoot, corpusRoot string) error {
	repoAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return err
	}
	repoAbs, err = filepath.EvalSymlinks(repoAbs)
	if err != nil {
		return fmt.Errorf("canonicalize synthcorpus root: %w", err)
	}
	corpusAbs, err := filepath.Abs(corpusRoot)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(repoAbs, corpusAbs)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return fmt.Errorf("generated-real root is inside synthcorpus worktree: %s", corpusRoot)
	}
	return nil
}

func runFingerprint(ctx context.Context, binary, root string, invocation Invocation) ([]byte, error) {
	args := []string{invocation.Command, root, "--format", invocation.Format, "--path-mode", invocation.PathMode}
	if invocation.FailOnEmpty {
		args = append(args, "--fail-on-empty")
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("decernor fingerprint failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func ParseNDJSON(data []byte) ([]Record, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, errors.New("NDJSON must be non-empty and newline-terminated")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var records []Record
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(line) == 0 {
			return nil, fmt.Errorf("line %d is empty", lineNumber)
		}
		record, err := parseRecord(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no records")
	}
	return records, nil
}

func parseRecord(line []byte) (Record, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil {
		return Record{}, err
	}
	required := map[string]bool{
		"schema_version": false, "path": false, "kind": false, "class": false,
		"algorithm": false, "fingerprint": false, "fingerprint_scheme": false,
		"confidence": false,
	}
	optional := map[string]bool{"key_id": true, "reason": true, "key_role": true}
	for field := range fields {
		if _, ok := required[field]; ok {
			required[field] = true
			continue
		}
		if !optional[field] {
			return Record{}, fmt.Errorf("unknown field %q", field)
		}
	}
	for field, present := range required {
		if !present {
			return Record{}, fmt.Errorf("missing required field %q", field)
		}
	}
	for _, field := range []string{"key_id", "reason", "key_role"} {
		if raw, present := fields[field]; present && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return Record{}, fmt.Errorf("field %q must be a string when present", field)
		}
	}
	var record Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return Record{}, err
	}
	if err := validateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateRecord(r Record) error {
	if r.SchemaVersion != recordSchemaVersion {
		return fmt.Errorf("unsupported schema_version %q", r.SchemaVersion)
	}
	if r.Path == "" {
		return errors.New("relative path is required")
	}
	if !validKinds[r.Kind] {
		return fmt.Errorf("invalid kind %q", r.Kind)
	}
	if !validClasses[r.Class] {
		return fmt.Errorf("invalid class %q", r.Class)
	}
	if !validAlgorithms[r.Algorithm] {
		return fmt.Errorf("invalid algorithm %q", r.Algorithm)
	}
	if !validSchemes[r.FingerprintScheme] {
		return fmt.Errorf("invalid fingerprint_scheme %q", r.FingerprintScheme)
	}
	if !validConfidence[r.Confidence] {
		return fmt.Errorf("invalid confidence %q", r.Confidence)
	}
	if r.KeyID != nil && *r.KeyID == "" {
		return errors.New("key_id must be non-empty when present")
	}
	if err := validateKeyRole(r); err != nil {
		return err
	}
	if r.Reason != nil && !validReasons[*r.Reason] {
		return fmt.Errorf("invalid reason %q", *r.Reason)
	}
	if err := validateRecordTuple(r); err != nil {
		return err
	}
	if r.Fingerprint == nil && r.Reason == nil {
		return errors.New("null fingerprint requires a fail-closed reason")
	}
	if r.Fingerprint != nil && *r.Fingerprint == "" {
		return errors.New("fingerprint must be non-empty when present")
	}
	if r.Fingerprint != nil && r.Reason != nil {
		return errors.New("non-null fingerprint must not carry a reason")
	}
	if r.Fingerprint != nil {
		if err := validateFingerprintEncoding(r); err != nil {
			return err
		}
	}
	return nil
}

func validateRecordTuple(r Record) error {
	var wantKind, wantAlgorithm string
	switch r.FingerprintScheme {
	case "openpgp-fingerprint-v1":
		wantKind, wantAlgorithm = "gpg", "openpgp-fingerprint"
	case "ssh-rfc4253-public-blob-sha256-v1":
		wantKind, wantAlgorithm = "ssh", "sha256"
	case "minisign-key-id-v1":
		wantKind, wantAlgorithm = "minisign", "minisign-key-id"
	case "minisign-public-blob-sha256-v1":
		wantKind, wantAlgorithm = "minisign", "sha256"
	default:
		return fmt.Errorf("invalid fingerprint_scheme %q", r.FingerprintScheme)
	}
	if r.Kind != wantKind || r.Algorithm != wantAlgorithm {
		return fmt.Errorf("incompatible kind/algorithm for fingerprint_scheme %q", r.FingerprintScheme)
	}
	return nil
}

func CheckStableOrdering(records []Record) error {
	for i := 1; i < len(records); i++ {
		if recordSortKey(records[i]) < recordSortKey(records[i-1]) {
			return fmt.Errorf("record %d sorts before record %d", i, i-1)
		}
	}
	return nil
}

func recordSortKey(r Record) string {
	id := optionalString(r.KeyID)
	if id == "" && r.Fingerprint != nil {
		id = *r.Fingerprint
	}
	if id == "" {
		id = optionalString(r.Reason)
	}
	return strings.Join([]string{r.Path, r.Kind, r.Class, r.FingerprintScheme, optionalString(r.KeyRole), id}, "\x00")
}

func ValidateGeneratedRecords(records []Record, p GeneratedProperties) error {
	if len(records) != p.ExpectedRecordCount {
		return fmt.Errorf("generated-real record count %d, want %d", len(records), p.ExpectedRecordCount)
	}
	if err := CheckStableOrdering(records); err != nil {
		return err
	}
	closed := make(map[string]bool, len(p.ClosedReasons))
	for _, reason := range p.ClosedReasons {
		closed[reason] = true
	}
	counts := make(map[string]int)
	for i, record := range records {
		if err := validateRecord(record); err != nil {
			return fmt.Errorf("record %d schema: %w", i, err)
		}
		if err := validateRelativePath(record.Path); err != nil {
			return fmt.Errorf("record %d path: %w", i, err)
		}
		counts[record.FingerprintScheme]++
		if record.Fingerprint == nil {
			if !closed[optionalString(record.Reason)] {
				return fmt.Errorf("record %d has an undeclared null reason", i)
			}
		}
	}
	if !equalCounts(counts, p.SchemeCounts) {
		return fmt.Errorf("generated-real scheme counts %#v, want %#v", counts, p.SchemeCounts)
	}
	for _, selector := range p.RequiredNullRecords {
		if countMatching(records, selector) != 1 {
			return fmt.Errorf("required null record %#v did not match exactly once", selector)
		}
	}
	for _, required := range p.RequiredPathSchemes {
		got := map[string]bool{}
		for _, record := range records {
			if record.Path == required.Path {
				got[record.FingerprintScheme] = true
			}
		}
		for _, scheme := range required.Schemes {
			if !got[scheme] {
				return fmt.Errorf("path %s missing required scheme %s", required.Path, scheme)
			}
		}
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" || filepath.IsAbs(path) || filepath.VolumeName(path) != "" || hasWindowsDrivePrefix(path) || strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return errors.New("not a forward-slash relative path")
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == ".." || strings.HasPrefix(clean, "../") || clean != path {
		return errors.New("path traversal or non-canonical path")
	}
	return nil
}

func hasWindowsDrivePrefix(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	letter := path[0]
	return letter >= 'A' && letter <= 'Z' || letter >= 'a' && letter <= 'z'
}

func validateKeyRole(r Record) error {
	gpgSuccess := r.Kind == "gpg" && r.Fingerprint != nil
	if gpgSuccess {
		if r.KeyRole == nil || (*r.KeyRole != "primary" && *r.KeyRole != "subkey") {
			return errors.New("gpg success requires key_role primary or subkey")
		}
		if r.KeyID == nil || !isUpperHex(*r.KeyID, 16) {
			return errors.New("gpg success requires uppercase 16-hex key_id")
		}
		fp := *r.Fingerprint
		if len(fp) < 16 || *r.KeyID != fp[len(fp)-16:] {
			return errors.New("gpg key_id must equal the fingerprint suffix")
		}
		return nil
	}
	if r.KeyRole != nil {
		return errors.New("key_role is prohibited except on successful gpg records")
	}
	return nil
}

func isUpperHex(value string, n int) bool {
	if len(value) != n {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'F' {
			continue
		}
		return false
	}
	return true
}

func validateFingerprintEncoding(r Record) error {
	value := *r.Fingerprint
	switch r.FingerprintScheme {
	case "ssh-rfc4253-public-blob-sha256-v1":
		encoded, ok := strings.CutPrefix(value, "SHA256:")
		if !ok {
			return fmt.Errorf("non-canonical SHA256 fingerprint for scheme %q", r.FingerprintScheme)
		}
		decoded, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(decoded) != sha256.Size || base64.RawStdEncoding.EncodeToString(decoded) != encoded {
			return fmt.Errorf("non-canonical SHA256 fingerprint for scheme %q", r.FingerprintScheme)
		}
	case "minisign-public-blob-sha256-v1":
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
			return fmt.Errorf("non-canonical minisign public-blob SHA-256 fingerprint")
		}
	case "minisign-key-id-v1":
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 8 || strings.ToUpper(hex.EncodeToString(decoded)) != value || optionalString(r.KeyID) != value {
			return fmt.Errorf("non-canonical minisign key id")
		}
	case "openpgp-fingerprint-v1":
		decoded, err := hex.DecodeString(value)
		if err != nil || (len(decoded) != 20 && len(decoded) != 32) || strings.ToUpper(hex.EncodeToString(decoded)) != value {
			return fmt.Errorf("non-canonical OpenPGP fingerprint")
		}
	default:
		return fmt.Errorf("unsupported fingerprint scheme %q", r.FingerprintScheme)
	}
	return nil
}

func countMatching(records []Record, selector RecordSelector) int {
	count := 0
	for _, r := range records {
		if r.Path == selector.Path && r.Kind == selector.Kind && r.Class == selector.Class &&
			r.FingerprintScheme == selector.FingerprintScheme && r.Fingerprint == nil && optionalString(r.Reason) == selector.Reason {
			count++
		}
	}
	return count
}

func validateRecordPaths(records []Record) error {
	for i, record := range records {
		if err := validateRelativePath(record.Path); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}
