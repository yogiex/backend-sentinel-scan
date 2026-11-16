package detector

import (
	"context"
	"fmt"
	"log"
)

type Detector struct {
	config  DetectionConfig
	plugins []*Plugin
	exec    *HTTPExecutor
	reg     *Registry
}

// New builds a Detector. The HTTP client is taken from cfg and shared by every
// plugin execution: creating one client per task throws away the connection pool
// and, worse, the egress budget attached to it.
func New(cfg DetectionConfig) *Detector {
	return &Detector{
		config: cfg,
		exec:   NewHTTPExecutor(cfg),
	}
}

// LoadPlugins loads the embedded plugin set and keeps its registry.
func (d *Detector) LoadPlugins() error {
	reg := NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		return fmt.Errorf("load embedded plugins: %w", err)
	}
	d.reg = reg
	d.plugins = reg.List()
	log.Printf("loaded %d detection plugins", len(d.plugins))
	return nil
}

// Registry exposes the loaded plugin set so callers can enumerate and resolve
// selectors without duplicating the load path.
func (d *Detector) Registry() *Registry { return d.reg }

func (d *Detector) Run(ctx context.Context, target string) []PluginResult {
	return d.RunWithPlugins(ctx, target, d.plugins)
}

// RunWithPlugins executes the given plugins against one target, returning only
// the ones that matched.
func (d *Detector) RunWithPlugins(ctx context.Context, target string, plugins []*Plugin) []PluginResult {
	if len(plugins) == 0 {
		return nil
	}
	exec := d.exec
	if exec == nil {
		exec = NewHTTPExecutor(d.config)
	}

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
					PluginID:          plugin.Metadata.ID,
					Target:            target,
					Matched:           true,
					Severity:          plugin.Metadata.Severity,
					Matches:           []MatchResult{match},
					ResponseBody:      response.Body,
					StatusCode:        response.StatusCode,
					ResponseTruncated: response.Truncated,
					Duration:          response.Duration,
				}
			}
		}
	}

	return PluginResult{PluginID: plugin.Metadata.ID, Target: target, Matched: false}
}

func (d *Detector) Plugins() []*Plugin {
	if d.reg != nil {
		return d.reg.List()
	}
	return append([]*Plugin(nil), d.plugins...)
}
