package detector

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

func ParsePlugin(data []byte) (*Plugin, error) {
	var plugin Plugin
	if err := yaml.Unmarshal(data, &plugin); err != nil {
		return nil, fmt.Errorf("failed to parse plugin: %w", err)
	}

	if plugin.Metadata.ID == "" {
		return nil, fmt.Errorf("plugin missing required field: metadata.id")
	}
	if plugin.Method == "" {
		plugin.Method = "GET"
	}
	if plugin.Path == "" {
		return nil, fmt.Errorf("plugin %s missing required field: path", plugin.Metadata.ID)
	}
	if plugin.Engine == "" {
		plugin.Engine = "http"
	}
	if plugin.Metadata.Severity == "" {
		plugin.Metadata.Severity = SeverityInfo
	}
	if len(plugin.Matchers) == 0 {
		return nil, fmt.Errorf("plugin %s has no matchers", plugin.Metadata.ID)
	}

	for i := range plugin.Matchers {
		m := &plugin.Matchers[i]
		if m.Condition == "" {
			m.Condition = "or"
		}
		if m.Location == "" {
			m.Location = "body"
		}
		if m.Threshold == 0 {
			m.Threshold = 10
		}
		if m.Timeout == 0 {
			m.Timeout = 5
		}
	}

	if plugin.Baseline != nil {
		if plugin.Baseline.Method == "" {
			plugin.Baseline.Method = "GET"
		}
		if plugin.Baseline.Path == "" {
			plugin.Baseline.Path = plugin.Path
		}
	}

	return &plugin, nil
}

func (p *Plugin) Validate() error {
	if p.Metadata.ID == "" {
		return fmt.Errorf("plugin id is required")
	}
	if p.Path == "" {
		return fmt.Errorf("plugin %s path is required", p.Metadata.ID)
	}
	if len(p.Matchers) == 0 {
		return fmt.Errorf("plugin %s must have at least one matcher", p.Metadata.ID)
	}
	return nil
}
