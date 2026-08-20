package main

import (
	"testing"
)

func TestAppVersion(t *testing.T) {
	if Version != "1.2.0" {
		t.Errorf("unexpected App Version: %s", Version)
	}
	if AppBanner == "" {
		t.Errorf("expected non-empty AppBanner")
	}
}
