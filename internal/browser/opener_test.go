package browser

import (
	"testing"
	"time"
)

func TestOpenBatchValidation(t *testing.T) {
	urls := []string{"https://example.com/1", "https://example.com/2"}
	err := OpenBatch(urls, 0, 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	emptyURLs := []string{}
	errEmpty := OpenBatch(emptyURLs, 5, 100*time.Millisecond)
	if errEmpty != nil {
		t.Errorf("unexpected error for empty urls: %v", errEmpty)
	}
}
