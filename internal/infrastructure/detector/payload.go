package detector

import (
	"net/url"
	"strings"
)

const (
	PlaceholderFUZZ = "FUZZ"
	PlaceholderHOST = "HOST"
	PlaceholderPORT = "PORT"
)

func ReplacePlaceholders(input string, targetURL string, payload string) string {
	result := strings.ReplaceAll(input, PlaceholderFUZZ, payload)
	return result
}

func ReplacePlaceholdersWithTarget(input string, targetHost string, targetPort string, payload string) string {
	result := strings.ReplaceAll(input, PlaceholderFUZZ, payload)
	result = strings.ReplaceAll(result, PlaceholderHOST, targetHost)
	result = strings.ReplaceAll(result, PlaceholderPORT, targetPort)
	return result
}

// EncodePayload percent-encodes a payload so it can be substituted into a URL
// path or query without changing the request's structure.
//
// url.QueryEscape is not used verbatim: it encodes a space as "+", which only
// means space inside a query string. In a path segment "+" stays a literal plus,
// so "1 AND SLEEP(5)" would reach the server mangled. Percent-encoding is valid
// in both positions.
func EncodePayload(payload string) string {
	return strings.ReplaceAll(url.QueryEscape(payload), "+", "%20")
}

func ResolveTargetPath(baseURL string, pathTemplate string, payload string) string {
	base := strings.TrimRight(baseURL, "/")
	resolvedPath := ReplacePlaceholders(pathTemplate, base, payload)

	if strings.HasPrefix(resolvedPath, "/") {
		return base + resolvedPath
	}
	return base + "/" + resolvedPath
}
