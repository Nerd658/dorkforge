package dorks

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Nerd658/dorkforge/internal/models"
)

func LoadCustomDorks(filePath string) ([]models.Dork, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read custom dorks file: %w", err)
	}

	var customList []models.Dork
	if err := json.Unmarshal(data, &customList); err != nil {
		return nil, fmt.Errorf("invalid json format in custom dorks file: %w", err)
	}

	for i, d := range customList {
		if d.ID == "" {
			d.ID = fmt.Sprintf("custom-%03d", i+1)
		}
		if d.Engine == "" {
			d.Engine = models.EngineGoogle
		}
		if d.Severity == "" {
			d.Severity = models.SeverityMedium
		}
		if d.Category == "" {
			d.Category = models.CategoryConfigs
		}
		customList[i] = d
	}

	return customList, nil
}
