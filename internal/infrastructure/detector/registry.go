package detector

import (
	"embed"
	"io/fs"
	"path/filepath"
)

//go:embed plugins/*.yaml
var embeddedPlugins embed.FS

type Registry struct {
	plugins []*Plugin
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) LoadEmbedded() error {
	entries, err := fs.ReadDir(embeddedPlugins, "plugins")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := fs.ReadFile(embeddedPlugins, filepath.Join("plugins", entry.Name()))
		if err != nil {
			continue
		}

		plugin, err := ParsePlugin(data)
		if err != nil {
			continue
		}

		r.plugins = append(r.plugins, plugin)
	}

	return nil
}

func (r *Registry) LoadFromDir(dir string) error {
	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}

	for _, entry := range entries {
		data, err := fs.ReadFile(embeddedPlugins, entry)
		if err != nil {
			plugin, parseErr := ParsePlugin(data)
			if parseErr == nil {
				r.plugins = append(r.plugins, plugin)
			}
		}
	}

	return nil
}

func (r *Registry) List() []*Plugin {
	return r.plugins
}

func (r *Registry) Get(id string) *Plugin {
	for _, p := range r.plugins {
		if p.Metadata.ID == id {
			return p
		}
	}
	return nil
}
