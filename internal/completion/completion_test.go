package completion

import (
	"bytes"
	"strings"
	"testing"
)

func TestSupportedShells(t *testing.T) {
	shells := SupportedShells()
	expected := []string{"bash", "zsh", "fish"}
	if len(shells) != len(expected) {
		t.Fatalf("expected %d shells, got %d", len(expected), len(shells))
	}
	for i, s := range expected {
		if shells[i] != s {
			t.Errorf("expected shells[%d] = %q, got %q", i, s, shells[i])
		}
	}
}

func TestIsSupportedShell(t *testing.T) {
	valid := []string{"bash", "zsh", "fish", "BASH", "Zsh", "Fish", "  bash  "}
	for _, s := range valid {
		if !IsSupportedShell(s) {
			t.Errorf("expected %q to be supported", s)
		}
	}

	invalid := []string{"powershell", "cmd", "sh", "ksh", "", "unknown"}
	for _, s := range invalid {
		if IsSupportedShell(s) {
			t.Errorf("expected %q to NOT be supported", s)
		}
	}
}

func TestGenerateBash(t *testing.T) {
	script := GenerateBash()
	if script == "" {
		t.Fatal("expected non-empty bash completion script")
	}

	requiredSnippets := []string{
		"complete -F _dorkforge dorkforge",
		"_dorkforge()",
		"scan",
		"subdomains",
		"list",
		"categories",
		"completion",
		"version",
		"--min-severity",
		"--category",
		"--engine",
		"--format",
		"configs",
		"secrets",
		"google",
		"shodan",
		"critical",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(script, snippet) {
			t.Errorf("GenerateBash script missing required snippet %q", snippet)
		}
	}
}

func TestGenerateZsh(t *testing.T) {
	script := GenerateZsh()
	if script == "" {
		t.Fatal("expected non-empty zsh completion script")
	}

	requiredSnippets := []string{
		"#compdef dorkforge",
		"_dorkforge()",
		"_arguments",
		"scan",
		"subdomains",
		"list",
		"categories",
		"completion",
		"configs",
		"secrets",
		"google",
		"shodan",
		"critical",
		"markdown",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(script, snippet) {
			t.Errorf("GenerateZsh script missing required snippet %q", snippet)
		}
	}
}

func TestGenerateFish(t *testing.T) {
	script := GenerateFish()
	if script == "" {
		t.Fatal("expected non-empty fish completion script")
	}

	requiredSnippets := []string{
		"complete -c dorkforge",
		"scan",
		"subdomains",
		"list",
		"categories",
		"completion",
		"configs",
		"secrets",
		"google",
		"shodan",
		"critical",
		"markdown",
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(script, snippet) {
			t.Errorf("GenerateFish script missing required snippet %q", snippet)
		}
	}
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		shell       string
		expectError bool
		contains    string
	}{
		{"bash", false, "complete -F _dorkforge dorkforge"},
		{"BASH", false, "complete -F _dorkforge dorkforge"},
		{"zsh", false, "#compdef dorkforge"},
		{"ZSH", false, "#compdef dorkforge"},
		{"fish", false, "complete -c dorkforge"},
		{"Fish", false, "complete -c dorkforge"},
		{"powershell", true, ""},
		{"tcsh", true, ""},
		{"", true, ""},
	}

	for _, tt := range tests {
		res, err := Generate(tt.shell)
		if tt.expectError {
			if err == nil {
				t.Errorf("Generate(%q) expected error, got nil", tt.shell)
			}
		} else {
			if err != nil {
				t.Errorf("Generate(%q) unexpected error: %v", tt.shell, err)
			}
			if !strings.Contains(res, tt.contains) {
				t.Errorf("Generate(%q) expected output to contain %q", tt.shell, tt.contains)
			}
		}
	}
}

func TestWriteCompletion(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCompletion(&buf, "bash")
	if err != nil {
		t.Fatalf("WriteCompletion unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "complete -F _dorkforge dorkforge") {
		t.Errorf("WriteCompletion buffer missing expected bash content")
	}

	var errBuf bytes.Buffer
	err = WriteCompletion(&errBuf, "unknown_shell")
	if err == nil {
		t.Error("WriteCompletion expected error for invalid shell, got nil")
	}
}
