package detector

import (
	"testing"
)

func TestMatchKeywordFound(t *testing.T) {
	result := MatchResponse("Hello world this is a test", 200, MatcherConfig{
		Type:     MatcherKeyword,
		Patterns: []string{"test"},
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Type != MatcherKeyword {
		t.Errorf("expected keyword matcher type")
	}
	if result.Pattern != "test" {
		t.Errorf("expected pattern 'test', got %q", result.Pattern)
	}
}

func TestMatchKeywordNotFound(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:     MatcherKeyword,
		Patterns: []string{"test"},
		Location: "body",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match")
	}
}

func TestMatchKeywordCaseInsensitive(t *testing.T) {
	result := MatchResponse("Hello SQL ERROR", 200, MatcherConfig{
		Type:     MatcherKeyword,
		Patterns: []string{"sql error"},
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected case-insensitive match")
	}
}

func TestMatchKeywordMultiplePatternsOr(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:      MatcherKeyword,
		Patterns:  []string{"test", "world"},
		Location:  "body",
		Condition: "or",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match with OR condition")
	}
}

func TestMatchKeywordMultiplePatternsAnd(t *testing.T) {
	result := MatchResponse("Hello world test", 200, MatcherConfig{
		Type:      MatcherKeyword,
		Patterns:  []string{"hello", "world"},
		Location:  "body",
		Condition: "and",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match with AND condition")
	}
}

func TestMatchKeywordAndConditionFails(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:      MatcherKeyword,
		Patterns:  []string{"hello", "nonexistent"},
		Location:  "body",
		Condition: "and",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match when one AND condition fails")
	}
}

func TestMatchKeywordNegative(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:     MatcherKeyword,
		Patterns: []string{"nothing"},
		Location: "body",
		Negative: true,
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match with negative condition (pattern absent)")
	}
}

func TestMatchKeywordNegativeFails(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:     MatcherKeyword,
		Patterns: []string{"world"},
		Location: "body",
		Negative: true,
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match with negative (pattern present)")
	}
}

func TestMatchRegexFound(t *testing.T) {
	result := MatchResponse("Error: ORA-00001 occurred", 200, MatcherConfig{
		Type:     MatcherRegex,
		Patterns: []string{"ORA-[0-9]{5}"},
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected regex match")
	}
	if result.Evidence != "ORA-00001" {
		t.Errorf("expected evidence 'ORA-00001', got %q", result.Evidence)
	}
}

func TestMatchRegexNotFound(t *testing.T) {
	result := MatchResponse("No error here", 200, MatcherConfig{
		Type:     MatcherRegex,
		Patterns: []string{"ORA-[0-9]{5}"},
		Location: "body",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no regex match")
	}
}

func TestMatchRegexInvalidPattern(t *testing.T) {
	result := MatchResponse("Hello", 200, MatcherConfig{
		Type:     MatcherRegex,
		Patterns: []string{"[invalid"},
		Location: "body",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match for invalid regex")
	}
}

func TestMatchRegexMultipleOr(t *testing.T) {
	result := MatchResponse("Hello world", 200, MatcherConfig{
		Type:      MatcherRegex,
		Patterns:  []string{"^Hello", "^World"},
		Location:  "body",
		Condition: "or",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match with OR regex")
	}
}

func TestMatchRegexMultipleAnd(t *testing.T) {
	result := MatchResponse("Hello world test", 200, MatcherConfig{
		Type:      MatcherRegex,
		Patterns:  []string{"Hello", "world"},
		Location:  "body",
		Condition: "and",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match with AND regex")
	}
}

func TestMatchRegexNegative(t *testing.T) {
	result := MatchResponse("Hello", 200, MatcherConfig{
		Type:     MatcherRegex,
		Patterns: []string{"notfound"},
		Location: "body",
		Negative: true,
	}, "payload")
	if !result.Matched {
		t.Fatal("expected regex negative match")
	}
}

func TestMatchStatusFound(t *testing.T) {
	result := MatchResponse("OK", 200, MatcherConfig{
		Type:     MatcherStatus,
		Patterns: []string{"200"},
		Location: "status",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match for status 200")
	}
}

func TestMatchStatusNotFound(t *testing.T) {
	result := MatchResponse("Not Found", 404, MatcherConfig{
		Type:     MatcherStatus,
		Patterns: []string{"200"},
		Location: "status",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match for status 404")
	}
}

func TestMatchStatusMultipleOr(t *testing.T) {
	result := MatchResponse("Moved", 301, MatcherConfig{
		Type:      MatcherStatus,
		Patterns:  []string{"301", "302"},
		Location:  "status",
		Condition: "or",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match for status 301 with OR")
	}
}

func TestMatchStatusAnd(t *testing.T) {
	result := MatchResponse("OK", 200, MatcherConfig{
		Type:      MatcherStatus,
		Patterns:  []string{"200", "200"},
		Location:  "status",
		Condition: "and",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match for status 200 with AND")
	}
}

func TestMatchStatusAndFails(t *testing.T) {
	result := MatchResponse("OK", 200, MatcherConfig{
		Type:      MatcherStatus,
		Patterns:  []string{"200", "404"},
		Location:  "status",
		Condition: "and",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match when one AND status fails")
	}
}

func TestMatchStatusNegative(t *testing.T) {
	result := MatchResponse("OK", 200, MatcherConfig{
		Type:     MatcherStatus,
		Patterns: []string{"404"},
		Location: "status",
		Negative: true,
	}, "payload")
	if !result.Matched {
		t.Fatal("expected match for negative status 404 (got 200)")
	}
}

func TestExtractEvidence(t *testing.T) {
	content := "prefix SQL_ERROR_MSG suffix"
	evidence := extractEvidence(content, "SQL_ERROR_MSG", 100)
	if evidence != content {
		t.Errorf("expected %q, got %q", content, evidence)
	}
}

func TestExtractEvidenceTruncated(t *testing.T) {
	content := "prefix SQL_ERROR_MSG suffix"
	evidence := extractEvidence(content, "SQL_ERROR_MSG", 10)
	if len(evidence) > 10 {
		t.Errorf("expected evidence <= 10 chars, got %d", len(evidence))
	}
}

func TestExtractEvidenceNotFound(t *testing.T) {
	content := "prefix suffix"
	evidence := extractEvidence(content, "NONEXISTENT", 100)
	if evidence != "" {
		t.Errorf("expected empty string, got %q", evidence)
	}
}

func TestMatchUnsupportedType(t *testing.T) {
	result := MatchResponse("Hello", 200, MatcherConfig{
		Type:     "unsupported",
		Patterns: []string{"test"},
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match for unsupported matcher type")
	}
}
