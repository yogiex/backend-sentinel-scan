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
//
// Callers that need to know whether the check actually happened must use
// CheckWithPlugins instead: matches alone cannot tell a clean target from a
// target that refused every connection.
func (d *Detector) RunWithPlugins(ctx context.Context, target string, plugins []*Plugin) []PluginResult {
	return d.CheckWithPlugins(ctx, target, plugins).Matches
}

func needsBaseline(matchers []MatcherConfig) bool {
	for _, m := range matchers {
		if m.Type == MatcherBoolean || m.Type == MatcherTimeBased {
			return true
		}
	}
	return false
}

func (d *Detector) Plugins() []*Plugin {
	if d.reg != nil {
		return d.reg.List()
	}
	return append([]*Plugin(nil), d.plugins...)
}
