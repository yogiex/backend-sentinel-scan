package detector

import "context"

// CheckWithPlugins executes plugins against one target and reports both the
// matches and how much work actually happened.
//
// The second half exists because matches alone lie by omission: a target that
// refused every connection used to look exactly like a clean target, so the
// scan was reported as "completed, no findings". Attempts are counted per
// request, including the baseline a boolean or time-based matcher needs,
// because a baseline that never arrived means the comparison never ran.
func (d *Detector) CheckWithPlugins(ctx context.Context, target string, plugins []*Plugin) CheckResult {
	if len(plugins) == 0 {
		return CheckResult{}
	}
	exec := d.exec
	if exec == nil {
		exec = NewHTTPExecutor(d.config)
	}

	var out CheckResult
	for _, plugin := range plugins {
		select {
		case <-ctx.Done():
			return out
		default:
		}

		result, stats := d.executePlugin(ctx, exec, plugin, target)
		out.Stats.Attempted += stats.Attempted
		out.Stats.Succeeded += stats.Succeeded
		out.Stats.Failed += stats.Failed
		if stats.LastError != nil {
			out.Stats.LastError = stats.LastError
		}
		if result.Matched {
			out.Matches = append(out.Matches, result)
		}
	}
	return out
}

// executePlugin runs one plugin and returns its result together with the
// request accounting. A payload that fails is counted and remembered instead of
// being skipped silently.
func (d *Detector) executePlugin(ctx context.Context, exec *HTTPExecutor, plugin *Plugin, target string) (PluginResult, CheckStats) {
	var stats CheckStats
	var baselineResponse *ExecutorResponse

	if needsBaseline(plugin.Matchers) {
		stats.Attempted++
		var err error
		baselineResponse, err = exec.ExecuteBaseline(ctx, target, plugin)
		if err != nil {
			stats.Failed++
			stats.LastError = err
			baselineResponse = nil
		} else {
			stats.Succeeded++
		}
	}

	noMatch := PluginResult{PluginID: plugin.Metadata.ID, Target: target, Matched: false}

	for i, payload := range plugin.Payloads {
		if d.config.MaxPayloadsPerPlugin > 0 && i >= d.config.MaxPayloadsPerPlugin {
			break
		}

		select {
		case <-ctx.Done():
			return noMatch, stats
		default:
		}

		stats.Attempted++
		response, err := exec.Execute(ctx, target, plugin, payload)
		if err != nil {
			stats.Failed++
			stats.LastError = err
			continue
		}
		stats.Succeeded++

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
				match = MatchResponseWithHeaders(response.Body, response.StatusCode, response.Headers, matcher, payload.Value)
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
				}, stats
			}
		}
	}

	return noMatch, stats
}
