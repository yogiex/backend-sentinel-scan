package template

type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info NucleiTemplateInfo `yaml:"info"`
}

func (t *NucleiTemplate) EngineType() string {
	if t.Info.Tags != nil {
		for _, tag := range t.Info.Tags {
			if tag == "headless" {
				return "headless"
			}
		}
	}
	return "http"
}

type NucleiTemplateInfo struct {
	Name     string   `yaml:"name"`
	Severity string   `yaml:"severity"`
	Tags     []string `yaml:"tags"`
}
