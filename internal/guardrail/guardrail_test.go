package guardrail

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareOutputRootRejectsNormalRepo(t *testing.T) {
	repo := initGitRepo(t)

	_, err := PrepareOutputRoot(filepath.Join(repo, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git worktree") {
		t.Fatalf("expected git worktree rejection, got %v", err)
	}
}

func TestPrepareOutputRootRejectsRepoWithInheritedGitDir(t *testing.T) {
	repo := initGitRepo(t)
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "no-such-git-dir"))

	_, err := PrepareOutputRoot(filepath.Join(repo, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git worktree") {
		t.Fatalf("expected git worktree rejection with inherited GIT_DIR, got %v", err)
	}
}

func TestPrepareOutputRootRejectsRepoWithInheritedGitWorkTree(t *testing.T) {
	repo := initGitRepo(t)
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_INDEX_FILE", filepath.Join(t.TempDir(), "index"))
	t.Setenv("GIT_CEILING_DIRECTORIES", repo)

	_, err := PrepareOutputRoot(filepath.Join(repo, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git worktree") {
		t.Fatalf("expected git worktree rejection with inherited GIT_WORK_TREE, got %v", err)
	}
}

func TestPrepareOutputRootRejectsLinkedWorktreeAndGitFile(t *testing.T) {
	mainRepo := initGitRepo(t)
	runGit(t, mainRepo, "config", "user.email", "synthcorpus-test@example.invalid")
	runGit(t, mainRepo, "config", "user.name", "synthcorpus test")
	runGit(t, mainRepo, "commit", "--allow-empty", "-m", "initial")

	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, mainRepo, "worktree", "add", linked, "-b", "linked-test")

	gitFile, err := os.Lstat(filepath.Join(linked, ".git"))
	if err != nil {
		t.Fatalf("expected linked worktree .git file: %v", err)
	}
	if gitFile.IsDir() {
		t.Fatalf("expected linked worktree .git to be a file")
	}

	_, err = PrepareOutputRoot(filepath.Join(linked, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git worktree") {
		t.Fatalf("expected linked worktree rejection, got %v", err)
	}
}

func TestPrepareOutputRootRejectsSymlinkToRepo(t *testing.T) {
	// Final component is a symlink: refuse before any resolve-through write.
	repo := initGitRepo(t)
	link := filepath.Join(t.TempDir(), "repo-link")
	if err := os.Symlink(repo, link); err != nil {
		t.Fatalf("create symlink-to-repo fixture: %v", err)
	}

	_, err := PrepareOutputRoot(link, false)
	if err == nil || !strings.Contains(err.Error(), "symlinked component") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestPrepareOutputRootCanonicalizesSymlinkedParentNonRepo(t *testing.T) {
	// Intermediate parent symlink into a non-repo: resolve to realpath, then
	// mint only on the realpath (never retain the symlink-bearing pathname).
	target := t.TempDir()
	parent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(target, parent); err != nil {
		t.Fatalf("create parent symlink fixture: %v", err)
	}

	root, err := PrepareOutputRoot(filepath.Join(parent, "dogfood"), false)
	if err != nil {
		t.Fatalf("expected canonicalized parent symlink path to pass: %v", err)
	}
	assertRealPath(t, root)
	if strings.Contains(root, "parent-link") {
		t.Fatalf("returned path retained symlink component: %q", root)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(target, "dogfood"))
	if err != nil {
		t.Fatalf("eval expected real dogfood path: %v", err)
	}
	if root != want {
		t.Fatalf("root = %q, want real target path %q", root, want)
	}
}

func TestPrepareOutputRootRejectsSymlinkedParentWorktree(t *testing.T) {
	// Intermediate parent symlink into a worktree: after realpath, git guard
	// must refuse before any write into the repo.
	repo := initGitRepo(t)
	parent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(repo, parent); err != nil {
		t.Fatalf("create parent symlink fixture: %v", err)
	}

	_, err := PrepareOutputRoot(filepath.Join(parent, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git worktree") {
		t.Fatalf("expected git worktree rejection via resolved parent symlink, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "dogfood")); !os.IsNotExist(err) {
		t.Fatalf("expected no write into worktree, got %v", err)
	}
}

func TestPrepareOutputRootForceThroughSymlinkedParentUsesRealPath(t *testing.T) {
	// Marker-owned directory on a real path, reached via a symlinked parent:
	// --force must operate on the realpath only (not retain the link path).
	realRoot := t.TempDir()
	realOut := filepath.Join(realRoot, "dogfood")
	if err := os.MkdirAll(realOut, DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarker(realOut, DefaultTool); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(realOut, "must-be-replaced.txt")
	if err := os.WriteFile(sentinel, []byte("old\n"), SecretPerm); err != nil {
		t.Fatal(err)
	}

	parent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(realRoot, parent); err != nil {
		t.Fatalf("create parent symlink fixture: %v", err)
	}

	root, err := PrepareOutputRoot(filepath.Join(parent, "dogfood"), true)
	if err != nil {
		t.Fatalf("expected force via resolved parent symlink to pass: %v", err)
	}
	assertRealPath(t, root)
	if strings.Contains(root, "parent-link") {
		t.Fatalf("force returned symlink-bearing path: %q", root)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("expected realpath contents replaced, got %v", err)
	}
	// Removing the parent link must not affect the returned realpath root.
	if err := os.Remove(parent); err != nil {
		t.Fatalf("remove parent symlink: %v", err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		t.Fatalf("realpath root must remain after link removal: err=%v info=%v", err, info)
	}
}

func TestPrepareOutputRootAllowsNonRepoDogfoodPath(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dogfooding", "decernor")

	root, err := PrepareOutputRoot(out, false)
	if err != nil {
		t.Fatalf("expected non-repo output path to pass: %v", err)
	}
	assertRealPath(t, root)
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("lstat created root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("created root is not a directory")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("created root is a symlink")
	}
	if got := info.Mode().Perm(); got != DirPerm {
		t.Fatalf("root mode = %o, want %o", got, DirPerm)
	}
}

func TestPrepareOutputRootForceRequiresRealMarker(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dogfood")
	if err := os.MkdirAll(out, DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "unowned.txt"), []byte("not ours\n"), SecretPerm); err != nil {
		t.Fatal(err)
	}

	_, err := PrepareOutputRoot(out, true)
	if err == nil || !strings.Contains(err.Error(), "ownership marker") {
		t.Fatalf("expected marker requirement, got %v", err)
	}
}

func TestPrepareOutputRootRejectsGitDirDescendant(t *testing.T) {
	repo := initGitRepo(t)
	gitDir := filepath.Join(repo, ".git")

	_, err := PrepareOutputRoot(filepath.Join(gitDir, "synthcorpus-out"), false)
	if err == nil || !strings.Contains(err.Error(), "git directory") {
		t.Fatalf("expected git directory rejection under .git, got %v", err)
	}
}

func TestPrepareOutputRootRejectsBareRepository(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	runGit(t, t.TempDir(), "init", "--bare", bare)

	_, err := PrepareOutputRoot(filepath.Join(bare, "dogfood"), false)
	if err == nil || !strings.Contains(err.Error(), "git directory") {
		t.Fatalf("expected bare repository rejection, got %v", err)
	}
}

func TestPrepareOutputRootRejectsNonRegularMarker(t *testing.T) {
	// Portable non-regular case: a directory at the marker path is not
	// ownership evidence. Special-file (FIFO) hang coverage lives in the
	// unix-tagged companion file so pure-Go unit tests compile on Windows.
	out := filepath.Join(t.TempDir(), "dogfood")
	if err := os.MkdirAll(out, DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(out, MarkerName), DirPerm); err != nil {
		t.Fatal(err)
	}

	_, err := PrepareOutputRoot(out, true)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected non-regular marker rejection, got %v", err)
	}
}

func TestPrepareOutputRootRejectsSymlinkedMarker(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dogfood")
	if err := os.MkdirAll(out, DirPerm); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "marker.json")
	if err := os.WriteFile(target, []byte(`{"kind":"`+MarkerKind+`","tool":"decernor"}`), SecretPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(out, MarkerName)); err != nil {
		t.Fatalf("create symlinked marker fixture: %v", err)
	}

	_, err := PrepareOutputRoot(out, true)
	if err == nil || !strings.Contains(err.Error(), "marker reached through symlink") {
		t.Fatalf("expected symlinked marker rejection, got %v", err)
	}
}

func TestPrepareOutputRootForceReplacesMarkerOwnedDirectory(t *testing.T) {
	out := filepath.Join(t.TempDir(), "dogfood")
	if err := os.MkdirAll(out, DirPerm); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarker(out, DefaultTool); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "old.txt"), []byte("old\n"), SecretPerm); err != nil {
		t.Fatal(err)
	}

	root, err := PrepareOutputRoot(out, true)
	if err != nil {
		t.Fatalf("expected marker-owned force to pass: %v", err)
	}
	assertRealPath(t, root)
	if _, err := os.Stat(filepath.Join(root, "old.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected old content removed, got %v", err)
	}
}

func assertRealPath(t *testing.T, path string) {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	if path != real {
		t.Fatalf("path %q is not fully real (EvalSymlinks=%q)", path, real)
	}
	if err := rejectSymlinksInPath(path); err != nil {
		t.Fatalf("symlink residual on returned path: %v", err)
	}
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, DirPerm); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "init")
	// Return the realpath so later joins match git's view after canonicalize.
	real, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatalf("EvalSymlinks repo: %v", err)
	}
	return real
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
