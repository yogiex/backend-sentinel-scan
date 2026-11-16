package detector

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed plugins/*.yaml
var embeddedPlugins embed.FS

// Registry holds the plugins available to the scanner.
//
// Loading is strict: a plugin that fails to parse aborts the load instead of
// being skipped. Skipping is how a scanner ends up running nine probes while
// its author believes it runs twelve, with no signal anywhere.
type Registry struct {
	plugins []*Plugin
	byID    map[string]*Plugin
}

func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]*Plugin)}
}

// LoadEmbedded loads the plugins compiled into the binary.
func (r *Registry) LoadEmbedded() error {
	entries, err := fs.ReadDir(embeddedPlugins, "plugins")
	if err != nil {
		return fmt.Errorf("read embedded plugins: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		data, err := fs.ReadFile(embeddedPlugins, filepath.Join("plugins", entry.Name()))
		if err != nil {
			return fmt.Errorf("read embedded plugin %s: %w", entry.Name(), err)
		}
		if err := r.add(data, entry.Name()); err != nil {
			return err
		}
	}
	return r.finish()
}

// LoadFromDir loads plugins from a directory on disk, replacing nothing: it is
// additive over whatever was loaded before.
func (r *Registry) LoadFromDir(dir string) error {
	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("list plugins in %s: %w", dir, err)
	}
	sort.Strings(entries)
	for _, entry := range entries {
		data, err := os.ReadFile(entry)
		if err != nil {
			return fmt.Errorf("read plugin %s: %w", entry, err)
		}
		if err := r.add(data, filepath.Base(entry)); err != nil {
			return err
		}
	}
	return r.finish()
}

func (r *Registry) add(data []byte, source string) error {
	plugin, err := ParsePlugin(data)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	if len(plugin.Payloads) == 0 {
		return fmt.Errorf("%s: plugin %s has no payloads, so it would issue no request", source, plugin.Metadata.ID)
	}
	if _, dup := r.byID[plugin.Metadata.ID]; dup {
		return fmt.Errorf("%s: duplicate plugin id %q", source, plugin.Metadata.ID)
	}
	r.byID[plugin.Metadata.ID] = plugin
	r.plugins = append(r.plugins, plugin)
	return nil
}

// finish rejects an empty registry: a scanner with no plugins reports every
// target as clean without touching the network.
func (r *Registry) finish() error {
	if len(r.plugins) == 0 {
		return fmt.Errorf("no plugins loaded")
	}
	return nil
}

// List returns the plugins in a stable order.
func (r *Registry) List() []*Plugin {
	out := make([]*Plugin, len(r.plugins))
	copy(out, r.plugins)
	return out
}

// Len returns how many plugins are loaded.
func (r *Registry) Len() int { return len(r.plugins) }

// Get returns the plugin with the given id, or nil.
func (r *Registry) Get(id string) *Plugin { return r.byID[id] }

// SelectorError reports a selector term that matched no plugin.
type SelectorError struct {
	Terms     []string
	Available []string
}

func (e *SelectorError) Error() string {
	return fmt.Sprintf("unknown template selector(s) %s; available plugins: %s",
		strings.Join(e.Terms, ", "), strings.Join(e.Available, ", "))
}

// Resolve expands template selectors into plugins.
//
// Grammar: comma-separated terms. A term matches a plugin id, a tag, or a
// severity, case-insensitively. An empty selector list means "every plugin".
// Unknown terms are an error rather than a silent no-op: a caller who asked for
// "xss" must not receive a scan of all nine probes.
func (r *Registry) Resolve(selectors string) ([]*Plugin, error) {
	terms := splitSelectors(selectors)
	if len(terms) == 0 {
		return r.List(), nil
	}

	seen := make(map[string]struct{}, len(r.plugins))
	out := make([]*Plugin, 0, len(r.plugins))
	var unknown []string

	for _, term := range terms {
		hits := r.match(term)
		if len(hits) == 0 {
			unknown = append(unknown, term)
			continue
		}
		for _, p := range hits {
			if _, ok := seen[p.Metadata.ID]; ok {
				continue
			}
			seen[p.Metadata.ID] = struct{}{}
			out = append(out, p)
		}
	}

	if len(unknown) > 0 {
		available := make([]string, 0, len(r.plugins))
		for _, p := range r.plugins {
			available = append(available, p.Metadata.ID)
		}
		return nil, &SelectorError{Terms: unknown, Available: available}
	}
	return out, nil
}

// match returns the plugins whose id, tags, or severity equal term.
func (r *Registry) match(term string) []*Plugin {
	term = strings.ToLower(term)
	var hits []*Plugin
	for _, p := range r.plugins {
		if strings.EqualFold(p.Metadata.ID, term) || strings.EqualFold(string(p.Metadata.Severity), term) {
			hits = append(hits, p)
			continue
		}
		for _, tag := range p.Metadata.Tags {
			if strings.EqualFold(tag, term) {
				hits = append(hits, p)
				break
			}
		}
	}
	return hits
}

func splitSelectors(selectors string) []string {
	parts := strings.FieldsFunc(selectors, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
