package detector

import (
	"testing"
)

func TestReplacePlaceholdersFUZZ(t *testing.T) {
	result := ReplacePlaceholders("/?id=FUZZ", "http://example.com", "' OR '1'='1")
	expected := "/?id=' OR '1'='1"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestReplacePlaceholdersNoFUZZ(t *testing.T) {
	result := ReplacePlaceholders("/api/users", "http://example.com", "test")
	expected := "/api/users"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestReplacePlaceholdersEmpty(t *testing.T) {
	result := ReplacePlaceholders("", "http://example.com", "test")
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestReplacePlaceholdersMultipleFUZZ(t *testing.T) {
	result := ReplacePlaceholders("/?q=FUZZ&s=FUZZ", "http://example.com", "<script>")
	expected := "/?q=<script>&s=<script>"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestReplacePlaceholdersWithTarget(t *testing.T) {
	result := ReplacePlaceholdersWithTarget("/redirect?host=HOST&port=PORT&q=FUZZ", "example.com", "8080", "test")
	expected := "/redirect?host=example.com&port=8080&q=test"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestEncodePayload(t *testing.T) {
	result := EncodePayload("<script>alert('xss')</script>")
	if result != "%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E" {
		t.Errorf("unexpected encoded result: %q", result)
	}
}

func TestEncodePayloadSimple(t *testing.T) {
	result := EncodePayload("hello")
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestResolveTargetPathWithSlash(t *testing.T) {
	result := ResolveTargetPath("http://example.com", "/?id=FUZZ", "test")
	if result != "http://example.com/?id=test" {
		t.Errorf("unexpected path: %q", result)
	}
}

func TestResolveTargetPathWithoutSlash(t *testing.T) {
	result := ResolveTargetPath("http://example.com", "api/users", "test")
	if result != "http://example.com/api/users" {
		t.Errorf("unexpected path: %q", result)
	}
}

func TestResolveTargetPathTrailingSlash(t *testing.T) {
	result := ResolveTargetPath("http://example.com/", "/api/users", "test")
	if result != "http://example.com/api/users" {
		t.Errorf("unexpected path: %q", result)
	}
}
