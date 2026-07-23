package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateWordlistPath(t *testing.T) {
	if err := validateWordlistPath(""); err != nil {
		t.Errorf("empty path (use embedded default) should be valid, got %v", err)
	}

	dir := t.TempDir()

	regular := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(regular, []byte("admin\nlogin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateWordlistPath(regular); err != nil {
		t.Errorf("regular file should be valid, got %v", err)
	}

	if err := validateWordlistPath(filepath.Join(dir, "does-not-exist.txt")); err == nil {
		t.Error("expected error for a nonexistent path")
	}

	if err := validateWordlistPath(dir); err == nil {
		t.Error("expected error for a directory path")
	}

	big := filepath.Join(dir, "big.txt")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxWordlistBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := validateWordlistPath(big); err == nil {
		t.Error("expected error for an oversized file")
	}
}
