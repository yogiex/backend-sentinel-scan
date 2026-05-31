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

func EncodePayload(payload string) string {
	return url.QueryEscape(payload)
}

func ResolveTargetPath(baseURL string, pathTemplate string, payload string) string {
	base := strings.TrimRight(baseURL, "/")
	resolvedPath := ReplacePlaceholders(pathTemplate, base, payload)

	if strings.HasPrefix(resolvedPath, "/") {
		return base + resolvedPath
	}
	return base + "/" + resolvedPath
}
