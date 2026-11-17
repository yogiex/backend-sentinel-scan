package application

import (
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

func TestNormalizeCrawlOptionsDisabledIsNil(t *testing.T) {
	got, err := normalizeCrawlOptions(nil)
	if err != nil || got != nil {
		t.Fatalf("nil crawl: got %+v, %v", got, err)
	}
	got, err = normalizeCrawlOptions(&entity.CrawlOptions{Enabled: false, MaxDepth: 99})
	if err != nil || got != nil {
		t.Fatalf("disabled crawl must be dropped, got %+v, %v", got, err)
	}
}

func TestNormalizeCrawlOptionsDefaults(t *testing.T) {
	got, err := normalizeCrawlOptions(&entity.CrawlOptions{Enabled: true})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.MaxDepth != defaultCrawlDepth || got.MaxPages != defaultCrawlPages {
		t.Fatalf("expected defaults %d/%d, got %+v", defaultCrawlDepth, defaultCrawlPages, got)
	}
	if !got.Enabled {
		t.Fatal("enabled flag must survive normalisation")
	}
}

func TestNormalizeCrawlOptionsRejectsOutOfRange(t *testing.T) {
	cases := map[string]*entity.CrawlOptions{
		"depth too deep": {Enabled: true, MaxDepth: maxCrawlDepth + 1},
		"negative depth": {Enabled: true, MaxDepth: -1},
		"pages zero-ish": {Enabled: true, MaxPages: -3},
		"pages too many": {Enabled: true, MaxPages: maxCrawlPages + 1},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeCrawlOptions(opts); err == nil {
				t.Fatalf("%s should be rejected", name)
			}
		})
	}
}

func TestNormalizeCrawlOptionsKeepsRobotsChoice(t *testing.T) {
	got, err := normalizeCrawlOptions(&entity.CrawlOptions{Enabled: true, MaxDepth: 1, MaxPages: 5, RespectRobots: false})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.RespectRobots {
		t.Fatal("an explicit respect_robots=false must be preserved")
	}
}
