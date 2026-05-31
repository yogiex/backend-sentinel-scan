package detector

import (
	"testing"
	"time"
)

func TestMatchErrorBasedMySQL(t *testing.T) {
	body := "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected MySQL error match")
	}
	if result.Pattern != "mysql" {
		t.Errorf("expected dbms 'mysql', got %q", result.Pattern)
	}
}

func TestMatchErrorBasedPostgres(t *testing.T) {
	body := "WARNING:  PostgreSQL ERROR: relation \"users\" does not exist"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected Postgres error match")
	}
	if result.Pattern != "postgresql" {
		t.Errorf("expected dbms 'postgresql', got %q", result.Pattern)
	}
}

func TestMatchErrorBasedMSSQL(t *testing.T) {
	body := "Unclosed quotation mark after the character string"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected MSSQL error match")
	}
	if result.Pattern != "mssql" {
		t.Errorf("expected dbms 'mssql', got %q", result.Pattern)
	}
}

func TestMatchErrorBasedOracle(t *testing.T) {
	body := "ORA-00942: table or view does not exist"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected Oracle error match")
	}
	if result.Pattern != "oracle" {
		t.Errorf("expected dbms 'oracle', got %q", result.Pattern)
	}
}

func TestMatchErrorBasedSQLite(t *testing.T) {
	body := "sqlite3.OperationalError: no such table: users"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if !result.Matched {
		t.Fatal("expected SQLite error match")
	}
	if result.Pattern != "sqlite" {
		t.Errorf("expected dbms 'sqlite', got %q", result.Pattern)
	}
}

func TestMatchErrorBasedNoMatch(t *testing.T) {
	body := "Normal response with no database error"
	result := MatchResponse(body, 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match for clean response")
	}
}

func TestMatchErrorBasedEmptyBody(t *testing.T) {
	result := MatchResponse("", 200, MatcherConfig{
		Type:     MatcherErrorBased,
		Location: "body",
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match for empty body")
	}
}

func TestMatchBooleanLengthDiff(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "Welcome back, user",
		StatusCode: 200,
		Duration:   10 * time.Millisecond,
	}
	attackBody := ""
	attackCode := 500

	result := MatchResponseWithBaseline(attackBody, attackCode, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "length",
		Threshold:  5,
	}, "payload", baseline)
	if !result.Matched {
		t.Fatal("expected boolean match based on length difference")
	}
}

func TestMatchBooleanNoDiff(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "Hello world",
		StatusCode: 200,
	}
	attackBody := "Hello world"

	result := MatchResponseWithBaseline(attackBody, 200, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "length",
		Threshold:  10,
	}, "payload", baseline)
	if result.Matched {
		t.Fatal("expected no boolean match for identical responses")
	}
}

func TestMatchBooleanCodeDiff(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "OK",
		StatusCode: 200,
	}
	attackBody := "Not Found"

	result := MatchResponseWithBaseline(attackBody, 404, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "code",
	}, "payload", baseline)
	if !result.Matched {
		t.Fatal("expected boolean match based on status code difference")
	}
}

func TestMatchBooleanNilBaseline(t *testing.T) {
	result := MatchResponseWithBaseline("body", 200, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "length",
	}, "payload", nil)
	if result.Matched {
		t.Fatal("expected no match with nil baseline")
	}
}

func TestMatchBooleanBodyDiff(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "User exists",
		StatusCode: 200,
	}

	result := MatchResponseWithBaseline("User does not exist", 200, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "body",
	}, "payload", baseline)
	if !result.Matched {
		t.Fatal("expected boolean match based on body difference")
	}
}

func TestMatchBooleanBodySame(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "User exists",
		StatusCode: 200,
	}

	result := MatchResponseWithBaseline("User exists", 200, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "body",
	}, "payload", baseline)
	if result.Matched {
		t.Fatal("expected no boolean match for identical bodies")
	}
}

func TestMatchBooleanNegative(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "Hello world",
		StatusCode: 200,
	}

	result := MatchResponseWithBaseline("Hello world", 200, MatcherConfig{
		Type:       MatcherBoolean,
		Comparison: "length",
		Threshold:  10,
		Negative:   true,
	}, "payload", baseline)
	if !result.Matched {
		t.Fatal("expected negative boolean match when responses are similar")
	}
}

func TestMatchTimeBasedDelay(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "OK",
		StatusCode: 200,
		Duration:   50 * time.Millisecond,
	}

	result := matchTimeBased(baseline, "OK", 200, 5.5, MatcherConfig{
		Type:    MatcherTimeBased,
		Timeout: 5,
	}, "payload")
	if !result.Matched {
		t.Fatal("expected time-based match for 5.5s vs 0.05s baseline")
	}
	if result.Evidence == "" {
		t.Error("expected non-empty evidence")
	}
}

func TestMatchTimeBasedNoDelay(t *testing.T) {
	baseline := &ExecutorResponse{
		Body:       "OK",
		StatusCode: 200,
		Duration:   50 * time.Millisecond,
	}

	result := matchTimeBased(baseline, "OK", 200, 0.06, MatcherConfig{
		Type:    MatcherTimeBased,
		Timeout: 5,
	}, "payload")
	if result.Matched {
		t.Fatal("expected no time-based match for 60ms vs 50ms baseline")
	}
}

func TestMatchTimeBasedNilBaseline(t *testing.T) {
	result := matchTimeBased(nil, "OK", 200, 5.5, MatcherConfig{
		Type:    MatcherTimeBased,
		Timeout: 5,
	}, "payload")
	if result.Matched {
		t.Fatal("expected no match with nil baseline")
	}
}

func TestCompareLengthDiff(t *testing.T) {
	if !CompareResponses("short", "this is a much longer string", CompareLength, 5) {
		t.Fatal("expected length comparison to detect difference")
	}
}

func TestCompareLengthWithinThreshold(t *testing.T) {
	if CompareResponses("hello", "hello!", CompareLength, 10) {
		t.Fatal("expected no diff for same-length with high threshold")
	}
}

func TestCompareBodyDifferent(t *testing.T) {
	if !CompareResponses("abc", "def", CompareBody, 0) {
		t.Fatal("expected body comparison to detect difference")
	}
}

func TestCompareBodySame(t *testing.T) {
	if CompareResponses("hello", "hello", CompareBody, 0) {
		t.Fatal("expected body comparison to return false for same content")
	}
}

func TestCompareSimilarityDiff(t *testing.T) {
	baseline := "aaaaaaaaaaaaaaaaaaaa"
	attack := "bbbbbbbbbb"

	if !CompareResponses(baseline, attack, CompareSimilarity, 40) {
		t.Fatal("expected similarity comparison to detect difference")
	}
}

func TestCompareSimilaritySame(t *testing.T) {
	if CompareResponses("hello world", "hello world", CompareSimilarity, 10) {
		t.Fatal("expected similarity comparison to return false for same content")
	}
}

func TestCompareSimilarityBothEmpty(t *testing.T) {
	if CompareResponses("", "", CompareSimilarity, 10) {
		t.Fatal("expected false for both empty strings")
	}
}

func TestCompareSimilarityOneEmpty(t *testing.T) {
	if !CompareResponses("", "something", CompareSimilarity, 100) {
		t.Fatal("expected true when one string is empty")
	}
}

func TestCompareDefaultMethod(t *testing.T) {
	if !CompareResponses("short", "very long content here", "", 5) {
		t.Fatal("expected default to use length method")
	}
}

func TestGetBodyLength(t *testing.T) {
	if GetBodyLength("hello") != 5 {
		t.Errorf("expected 5, got %d", GetBodyLength("hello"))
	}
	if GetBodyLength("") != 0 {
		t.Errorf("expected 0, got %d", GetBodyLength(""))
	}
}

func TestFormatInt(t *testing.T) {
	if formatInt(0) != "0" {
		t.Errorf("expected '0', got %q", formatInt(0))
	}
	if formatInt(123) != "123" {
		t.Errorf("expected '123', got %q", formatInt(123))
	}
	if formatInt(-5) != "-5" {
		t.Errorf("expected '-5', got %q", formatInt(-5))
	}
}

func TestFormatFloat(t *testing.T) {
	result := formatFloat(5.5)
	if result == "" {
		t.Fatal("expected non-empty formatted float")
	}
}

func TestMatchPatterns(t *testing.T) {
	result := matchPatterns("error: SQL syntax", MatcherConfig{
		Patterns: []string{"SQL syntax"},
	}, "payload")
	if !result.Matched {
		t.Fatal("expected pattern match")
	}
}

func TestMatchPatternsNotFound(t *testing.T) {
	result := matchPatterns("clean response", MatcherConfig{
		Patterns: []string{"SQL syntax"},
	}, "payload")
	if result.Matched {
		t.Fatal("expected no pattern match")
	}
}
