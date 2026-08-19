package models

import (
	"testing"
)

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev      Severity
		expected int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		if got := tt.sev.Rank(); got != tt.expected {
			t.Errorf("Rank() for %v = %v; want %v", tt.sev, got, tt.expected)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected Severity
		hasErr   bool
	}{
		{"critical", SeverityCritical, false},
		{"HIGH", SeverityHigh, false},
		{"med", SeverityMedium, false},
		{"low", SeverityLow, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		got, err := ParseSeverity(tt.input)
		if (err != nil) != tt.hasErr {
			t.Errorf("ParseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.hasErr)
		}
		if got != tt.expected {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsValidCategory(t *testing.T) {
	if !IsValidCategory("configs") {
		t.Errorf("expected 'configs' to be valid")
	}
	if !IsValidCategory("api-endpoints") {
		t.Errorf("expected 'api-endpoints' to be valid")
	}
	if IsValidCategory("non-existent-cat") {
		t.Errorf("expected 'non-existent-cat' to be invalid")
	}
}
