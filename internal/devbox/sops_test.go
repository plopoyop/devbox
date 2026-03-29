// Copyright 2024 Jetify Inc. and contributors. All rights reserved.
// Use of this source code is governed by the license in the LICENSE file.

package devbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSopsDecryptJSON_FlatMap(t *testing.T) {
	// Create a mock sops binary that outputs known JSON.
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte(`#!/bin/sh
echo '{"DB_PASSWORD":"secret123","API_KEY":"abc","PORT":5432,"DEBUG":true,"EMPTY":null}'
`), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	result, err := sopsDecryptJSON(t.Context(), mockSops, "dummy.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"DB_PASSWORD": "secret123",
		"API_KEY":     "abc",
		"PORT":        "5432",
		"DEBUG":       "true",
		"EMPTY":       "",
	}
	for k, want := range expected {
		if got := result[k]; got != want {
			t.Errorf("key %q: got %q, want %q", k, got, want)
		}
	}
	if len(result) != len(expected) {
		t.Errorf("got %d keys, want %d", len(result), len(expected))
	}
}

func TestSopsDecryptYAML_FlatMap(t *testing.T) {
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte("#!/bin/sh\nprintf 'DB_PASSWORD: secret123\\nAPI_KEY: abc\\nPORT: 5432\\nDEBUG: true\\nEMPTY: null\\n'\n"), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	result, err := sopsDecryptYAML(t.Context(), mockSops, "dummy.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"DB_PASSWORD": "secret123",
		"API_KEY":     "abc",
		"PORT":        "5432",
		"DEBUG":       "true",
		"EMPTY":       "",
	}
	for k, want := range expected {
		if got := result[k]; got != want {
			t.Errorf("key %q: got %q, want %q", k, got, want)
		}
	}
	if len(result) != len(expected) {
		t.Errorf("got %d keys, want %d", len(result), len(expected))
	}
}

func TestSopsDecryptYAML_NestedValueError(t *testing.T) {
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte("#!/bin/sh\nprintf 'DB:\\n  HOST: localhost\\n  PORT: 5432\\n'\n"), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sopsDecryptYAML(t.Context(), mockSops, "nested.yaml")
	if err == nil {
		t.Fatal("expected error for nested values, got nil")
	}
	if got := err.Error(); !contains(got, "nested value") {
		t.Errorf("error should mention nested value, got: %s", got)
	}
}

func TestSopsDecryptJSON_NestedValueError(t *testing.T) {
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte(`#!/bin/sh
echo '{"DB":{"HOST":"localhost","PORT":5432}}'
`), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sopsDecryptJSON(t.Context(), mockSops, "nested.json")
	if err == nil {
		t.Fatal("expected error for nested values, got nil")
	}
	if got := err.Error(); !contains(got, "nested value") {
		t.Errorf("error should mention nested value, got: %s", got)
	}
}

func TestSopsDecryptDotenv(t *testing.T) {
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte(`#!/bin/sh
printf 'DB_HOST=localhost\nDB_PORT=5432\n# comment\nAPI_KEY=secret\n'
`), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	result, err := sopsDecryptDotenv(t.Context(), mockSops, "secrets.env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]string{
		"DB_HOST": "localhost",
		"DB_PORT": "5432",
		"API_KEY": "secret",
	}
	for k, want := range expected {
		if got := result[k]; got != want {
			t.Errorf("key %q: got %q, want %q", k, got, want)
		}
	}
	if len(result) != len(expected) {
		t.Errorf("got %d keys, want %d", len(result), len(expected))
	}
}

func TestSopsDecryptJSON_SopsFailure(t *testing.T) {
	tmpDir := t.TempDir()
	mockSops := filepath.Join(tmpDir, "sops")
	err := os.WriteFile(mockSops, []byte(`#!/bin/sh
echo "error: could not decrypt" >&2
exit 1
`), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	_, err = sopsDecryptJSON(t.Context(), mockSops, "bad.json")
	if err == nil {
		t.Fatal("expected error for sops failure, got nil")
	}
	if got := err.Error(); !contains(got, "could not decrypt") {
		t.Errorf("error should contain sops stderr, got: %s", got)
	}
}

func TestFindSopsBinary_NotFound(t *testing.T) {
	// Use a non-existent project dir and ensure PATH doesn't contain sops.
	t.Setenv("PATH", t.TempDir())

	_, err := findSopsBinary(t.TempDir())
	if err == nil {
		t.Fatal("expected error when sops not found, got nil")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
