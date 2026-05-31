package detector

import (
	"context"
	"fmt"
	"log"
)

type Detector struct {
	config  DetectionConfig
	plugins []*Plugin
}

func New(cfg DetectionConfig) *Detector {
	return &Detector{
		config:  cfg,
		plugins: nil,
	}
}

func (d *Detector) LoadPlugins() error {
	reg := NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		return fmt.Errorf("failed to load embedded plugins: %w", err)
	}
	d.plugins = reg.List()
	log.Printf("Loaded %d detection plugins", len(d.plugins))
	return nil
}

func (d *Detector) Run(ctx context.Context, target string) []PluginResult {
	return d.RunWithPlugins(ctx, target, d.plugins)
}

func (d *Detector) RunWithPlugins(ctx context.Context, target string, plugins []*Plugin) []PluginResult {
	if len(plugins) == 0 {
		return nil
	}

	exec := NewHTTPExecutor(d.config)

	var results []PluginResult
	for _, plugin := range plugins {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		result := d.executePlugin(ctx, exec, plugin, target)
		if result.Matched {
			results = append(results, result)
		}
	}

	return results
}

func needsBaseline(matchers []MatcherConfig) bool {
	for _, m := range matchers {
		if m.Type == MatcherBoolean || m.Type == MatcherTimeBased {
			return true
		}
	}
	return false
}

func (d *Detector) executePlugin(ctx context.Context, exec *HTTPExecutor, plugin *Plugin, target string) PluginResult {
	var baselineResponse *ExecutorResponse

	if needsBaseline(plugin.Matchers) {
		var err error
		baselineResponse, err = exec.ExecuteBaseline(ctx, target, plugin)
		if err != nil {
			baselineResponse = nil
		}
	}

	for i, payload := range plugin.Payloads {
		if d.config.MaxPayloadsPerPlugin > 0 && i >= d.config.MaxPayloadsPerPlugin {
			break
		}

		select {
		case <-ctx.Done():
			return PluginResult{PluginID: plugin.Metadata.ID, Target: target, Matched: false}
		default:
		}

		response, err := exec.Execute(ctx, target, plugin, payload)
		if err != nil {
			continue
		}

		for _, matcher := range plugin.Matchers {
			var match MatchResult
			if matcher.Type == MatcherTimeBased && baselineResponse != nil {
				match = matchTimeBased(
					baselineResponse,
					response.Body,
					response.StatusCode,
					response.Duration.Seconds(),
					matcher,
					payload.Value,
				)
			} else if baselineResponse != nil && (matcher.Type == MatcherBoolean) {
				match = MatchResponseWithBaseline(response.Body, response.StatusCode, matcher, payload.Value, baselineResponse)
			} else {
				match = MatchResponse(response.Body, response.StatusCode, matcher, payload.Value)
			}

			if match.Matched {
				return PluginResult{
					PluginID:     plugin.Metadata.ID,
					Target:       target,
					Matched:      true,
					Severity:     plugin.Metadata.Severity,
					Matches:      []MatchResult{match},
					ResponseBody: response.Body,
				}
			}
		}
	}

	return PluginResult{PluginID: plugin.Metadata.ID, Target: target, Matched: false}
}

func (d *Detector) Plugins() []*Plugin {
	return d.plugins
}
