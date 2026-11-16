package crawler

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

func resolveBaseURL(doc *html.Node, fallback *url.URL) *url.URL {
	var f func(*html.Node) *url.URL
	f = func(n *html.Node) *url.URL {
		if n.Type == html.ElementNode && n.Data == "head" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && c.Data == "base" {
					for _, attr := range c.Attr {
						if attr.Key == "href" {
							base, err := url.Parse(attr.Val)
							if err == nil {
								return base
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if result := f(c); result != nil {
				return result
			}
		}
		return nil
	}
	if result := f(doc); result != nil {
		return result
	}
	return fallback
}

func parseLinks(body string, baseURL *url.URL) []string {
	unique := make(map[string]bool)
	var links []string

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	effectiveBase := resolveBaseURL(doc, baseURL)

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					href := strings.TrimSpace(attr.Val)
					if href == "" {
						continue
					}

					absolute := resolveURL(href, effectiveBase)
					if absolute == "" {
						continue
					}

					if !unique[absolute] {
						unique[absolute] = true
						links = append(links, absolute)
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return links
}

func parseForms(body string, baseURL *url.URL) []Form {
	var forms []Form

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := Form{Method: "GET", Action: baseURL.String()}
			for _, attr := range n.Attr {
				switch attr.Key {
				case "action":
					if attr.Val != "" {
						form.Action = resolveURL(attr.Val, baseURL)
					}
				case "method":
					form.Method = strings.ToUpper(attr.Val)
				}
			}

			var extractInputs func(*html.Node)
			extractInputs = func(node *html.Node) {
				if node.Type == html.ElementNode {
					switch node.Data {
					case "input":
						input := FormInput{}
						for _, attr := range node.Attr {
							switch attr.Key {
							case "name":
								input.Name = attr.Val
							case "type":
								input.Type = attr.Val
							}
						}
						if input.Type == "" {
							input.Type = "text"
						}
						if input.Name != "" {
							form.Inputs = append(form.Inputs, input)
						}
					case "textarea":
						input := FormInput{Type: "textarea"}
						for _, attr := range node.Attr {
							if attr.Key == "name" {
								input.Name = attr.Val
							}
						}
						if input.Name != "" {
							form.Inputs = append(form.Inputs, input)
						}
					case "select":
						input := FormInput{Type: "select"}
						for _, attr := range node.Attr {
							if attr.Key == "name" {
								input.Name = attr.Val
							}
						}
						if input.Name != "" {
							form.Inputs = append(form.Inputs, input)
						}
					}
				}
				for c := node.FirstChild; c != nil; c = c.NextSibling {
					extractInputs(c)
				}
			}
			extractInputs(n)

			forms = append(forms, form)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return forms
}

func parseAssets(body string, baseURL *url.URL) []string {
	unique := make(map[string]bool)
	var assets []string

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var attrKey, attrVal string
			switch n.Data {
			case "script":
				attrKey = "src"
			case "link":
				attrKey = "href"
			case "iframe", "img":
				attrKey = "src"
			}

			if attrKey != "" {
				for _, attr := range n.Attr {
					if attr.Key == attrKey {
						attrVal = strings.TrimSpace(attr.Val)
						break
					}
				}
			}

			if attrVal != "" {
				absolute := resolveURL(attrVal, baseURL)
				if absolute != "" && !unique[absolute] {
					unique[absolute] = true
					assets = append(assets, absolute)
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return assets
}

func resolveURL(href string, base *url.URL) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") {
		return ""
	}

	if strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") ||
		strings.HasPrefix(href, "tel:") ||
		strings.HasPrefix(href, "data:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	if parsed.IsAbs() {
		return parsed.String()
	}

	resolved := base.ResolveReference(parsed)
	return resolved.String()
}


// filterLinksByScope keeps only links allowed by the crawl scope. It is
// exercised by parser tests and kept for the discovery providers.
//
//nolint:unused // used by parser_test.go
func filterLinksByScope(links []string, seedURLs []string, scope *ScopeFilter) []string {
	if scope == nil {
		return links
	}
	var filtered []string
	for _, link := range links {
		if scope.Allows(link, seedURLs) {
			filtered = append(filtered, link)
		}
	}
	return filtered
}
