package detector

import (
	"net/http"
	"regexp"
	"strings"
)

func MatchResponse(body string, statusCode int, matcher MatcherConfig, payload string) MatchResult {
	return matchResponse(body, statusCode, nil, matcher, payload, nil)
}

// MatchResponseWithHeaders is the form the engine uses: it carries the response
// headers so a matcher can read Location or any other header.
func MatchResponseWithHeaders(body string, statusCode int, headers http.Header, matcher MatcherConfig, payload string) MatchResult {
	return matchResponse(body, statusCode, headers, matcher, payload, nil)
}

func MatchResponseWithBaseline(body string, statusCode int, matcher MatcherConfig, payload string, baseline *ExecutorResponse) MatchResult {
	return matchResponse(body, statusCode, nil, matcher, payload, baseline)
}

func matchResponse(body string, statusCode int, headers http.Header, matcher MatcherConfig, payload string, baseline *ExecutorResponse) MatchResult {
	switch matcher.Type {
	case MatcherKeyword:
		return matchKeyword(matcherContent(body, headers, matcher), statusCode, matcher, payload)
	case MatcherRegex:
		return matchRegex(matcherContent(body, headers, matcher), statusCode, matcher, payload)
	case MatcherStatus:
		return matchStatus(body, statusCode, matcher, payload)
	case MatcherErrorBased:
		return matchErrorBased(body, matcher, payload)
	case MatcherBoolean:
		return matchBoolean(baseline, body, statusCode, matcher, payload)
	case MatcherTimeBased:
		return matchTimeBased(baseline, body, statusCode, 0, matcher, payload)
	default:
		return MatchResult{Matched: false}
	}
}

// matcherContent selects what a content matcher is allowed to read. Keyword and
// regex matchers used to read the body no matter what "location" said, so a
// header check silently inspected the wrong data and could never fire.
func matcherContent(body string, headers http.Header, matcher MatcherConfig) string {
	if matcher.Location != MatcherLocationHeader {
		return body
	}
	if headers == nil || matcher.HeaderName == "" {
		return ""
	}
	return strings.Join(headers.Values(matcher.HeaderName), "\n")
}

func matchKeyword(body string, statusCode int, matcher MatcherConfig, payload string) MatchResult {
	content := body
	andMode := matcher.Condition == "and"

	if !andMode {
		for _, pattern := range matcher.Patterns {
			found := strings.Contains(strings.ToLower(content), strings.ToLower(pattern))
			if matcher.Negative {
				found = !found
			}
			if found {
				return MatchResult{
					Matched: true, Type: MatcherKeyword,
					Pattern: pattern, Evidence: extractEvidence(content, pattern, 100), Payload: payload,
				}
			}
		}
		return MatchResult{Matched: false}
	}

	var lastEvidence string
	for _, pattern := range matcher.Patterns {
		found := strings.Contains(strings.ToLower(content), strings.ToLower(pattern))
		if matcher.Negative {
			found = !found
		}
		if !found {
			return MatchResult{Matched: false}
		}
		lastEvidence = extractEvidence(content, pattern, 100)
	}

	if len(matcher.Patterns) > 0 {
		return MatchResult{Matched: true, Type: MatcherKeyword, Pattern: matcher.Patterns[0], Evidence: lastEvidence, Payload: payload}
	}
	return MatchResult{Matched: false}
}

func matchRegex(body string, statusCode int, matcher MatcherConfig, payload string) MatchResult {
	content := body
	andMode := matcher.Condition == "and"

	if !andMode {
		for _, pattern := range matcher.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			loc := re.FindString(content)
			found := loc != ""
			if matcher.Negative {
				found = !found
			}
			if found {
				return MatchResult{
					Matched: true, Type: MatcherRegex,
					Pattern: pattern, Evidence: loc, Payload: payload,
				}
			}
		}
		return MatchResult{Matched: false}
	}

	var lastEvidence string
	for _, pattern := range matcher.Patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		loc := re.FindString(content)
		found := loc != ""
		if matcher.Negative {
			found = !found
		}
		if !found {
			return MatchResult{Matched: false}
		}
		lastEvidence = loc
	}

	if len(matcher.Patterns) > 0 {
		return MatchResult{Matched: true, Type: MatcherRegex, Pattern: matcher.Patterns[0], Evidence: lastEvidence, Payload: payload}
	}
	return MatchResult{Matched: false}
}

func matchStatus(body string, statusCode int, matcher MatcherConfig, payload string) MatchResult {
	targetCode := statusCode
	andMode := matcher.Condition == "and"

	if !andMode {
		for _, pattern := range matcher.Patterns {
			var expectedCode int
			n, err := parseStrictInt(pattern, &expectedCode)
			matched := err == nil && n > 0 && expectedCode == targetCode
			if matcher.Negative {
				matched = !matched
			}
			if matched {
				return MatchResult{
					Matched: true, Type: MatcherStatus,
					Pattern: pattern, Evidence: pattern, Payload: payload,
				}
			}
		}
		return MatchResult{Matched: false}
	}

	for _, pattern := range matcher.Patterns {
		var expectedCode int
		n, err := parseStrictInt(pattern, &expectedCode)
		matched := err == nil && n > 0 && expectedCode == targetCode
		if matcher.Negative {
			matched = !matched
		}
		if !matched {
			return MatchResult{Matched: false}
		}
	}

	if len(matcher.Patterns) > 0 {
		return MatchResult{Matched: true, Type: MatcherStatus, Pattern: matcher.Patterns[0], Evidence: matcher.Patterns[0], Payload: payload}
	}
	return MatchResult{Matched: false}
}

func extractEvidence(content string, pattern string, maxLen int) string {
	idx := strings.Index(strings.ToLower(content), strings.ToLower(pattern))
	if idx < 0 {
		return ""
	}

	start := idx - 20
	if start < 0 {
		start = 0
	}

	end := idx + len(pattern) + 20
	if end > len(content) {
		end = len(content)
	}

	evidence := content[start:end]
	if len(evidence) > maxLen {
		evidence = evidence[:maxLen]
	}

	return evidence
}

func parseStrictInt(s string, out *int) (int, error) {
	*out = 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nil
		}
		*out = *out*10 + int(c-'0')
	}
	return 1, nil
}
