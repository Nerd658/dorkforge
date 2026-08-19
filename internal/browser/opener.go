package browser

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

func OpenURL(urlStr string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", urlStr)
	case "darwin":
		cmd = exec.Command("open", urlStr)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", urlStr)
	default:
		return fmt.Errorf("unsupported operating system for browser opening: %s", runtime.GOOS)
	}

	return cmd.Start()
}

func OpenBatch(urls []string, batchSize int, delay time.Duration) error {
	if batchSize <= 0 {
		batchSize = 5
	}
	if delay <= 0 {
		delay = 1500 * time.Millisecond
	}

	total := len(urls)
	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}

		fmt.Printf("Opening browser batch (%d-%d / %d)...\n", i+1, end, total)
		for j := i; j < end; j++ {
			if err := OpenURL(urls[j]); err != nil {
				fmt.Printf("Warning: failed to open URL: %s (%v)\n", urls[j], err)
			}
		}

		if end < total {
			time.Sleep(delay)
		}
	}

	return nil
}
