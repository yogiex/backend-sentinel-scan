package detector

import (
	"regexp"
	"strings"
)

type DBMS string

const (
	DBMSMySQL    DBMS = "mysql"
	DBMSPostgres DBMS = "postgresql"
	DBMSMSSQL    DBMS = "mssql"
	DBMSOracle   DBMS = "oracle"
	DBMSSQLite   DBMS = "sqlite"
)

var dbmsErrorPatterns = map[DBMS][]*regexp.Regexp{
	DBMSMySQL: compilePatterns([]string{
		"SQL syntax.*MySQL",
		"Warning.*mysql_.*",
		"You have an error in your SQL syntax",
		"MySQLSyntaxErrorException",
		"valid MySQL result",
		"check the manual that corresponds to your MySQL",
		"Unknown column.*in 'field list'",
		"Duplicate entry.*for key",
		"Data too long for column",
		"Table.*doesn't exist",
	}),
	DBMSPostgres: compilePatterns([]string{
		"PostgreSQL.*ERROR",
		"WARNING:  PostgreSQL",
		"psql:.*ERROR",
		"division by zero.*PostgreSQL",
		"pg_query",
		"ERROR:.*relation.*does not exist",
		"ERROR:.*column.*does not exist",
		"ERROR:.*syntax error at or near",
	}),
	DBMSMSSQL: compilePatterns([]string{
		"Microsoft OLE DB Provider for SQL Server",
		"Driver.*SQL Server",
		"ODBC SQL Server Driver",
		"Unclosed quotation mark after",
		"SQLServer JDBC Driver",
		"com.microsoft.sqlserver",
		"Line.*[0-9]+.*Incorrect syntax",
		"Msg.*[0-9]+.*Level.*[0-9]+.*State",
		"SQLSTATE\\[\\d+\\]",
	}),
	DBMSOracle: compilePatterns([]string{
		"ORA-[0-9]{5}",
		"Oracle.*Driver",
		"oracle\\.jdbc",
		"Oracle JDBC Driver",
		"PL/SQL.*error",
		"ORA-00001: unique constraint",
		"ORA-00942: table or view does not exist",
	}),
	DBMSSQLite: compilePatterns([]string{
		"SQLite/JDBCDriver",
		"SQLite.Exception",
		"sqlite_error",
		"sqlite3\\.OperationalError",
		"UNIQUE constraint failed",
		"table.*has no column named",
	}),
}

type ErrorMatch struct {
	DBMS   DBMS
	Match  string
}

func compilePatterns(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func matchErrorBased(body string, matcher MatcherConfig, payload string) MatchResult {
	andMode := matcher.Condition == "and"
	var firstMatch *ErrorMatch

	for dbms, patterns := range dbmsErrorPatterns {
		for _, re := range patterns {
			loc := re.FindString(body)
			if loc != "" {
				if firstMatch == nil {
					firstMatch = &ErrorMatch{DBMS: dbms, Match: loc}
				}
				if !andMode {
					return MatchResult{
						Matched: true, Type: MatcherErrorBased,
						Pattern: string(dbms), Evidence: loc, Payload: payload,
					}
				}
			}
		}
	}

	if andMode && firstMatch != nil {
		return MatchResult{
			Matched: true, Type: MatcherErrorBased,
			Pattern: string(firstMatch.DBMS), Evidence: firstMatch.Match, Payload: payload,
		}
	}

	return MatchResult{Matched: false}
}

func matchBoolean(baseline *ExecutorResponse, attackBody string, attackCode int, matcher MatcherConfig, payload string) MatchResult {
	if baseline == nil {
		return MatchResult{Matched: false, Type: MatcherBoolean, Payload: payload}
	}

	comparison := matcher.Comparison
	if comparison == "" {
		comparison = "length"
	}
	threshold := matcher.Threshold
	if threshold <= 0 {
		threshold = 10
	}

	switch comparison {
	case "code":
		different := attackCode != baseline.StatusCode
		if matcher.Negative {
			different = !different
		}
		if different {
			return MatchResult{
				Matched: true, Type: MatcherBoolean,
				Pattern: comparison, Evidence: intToString(attackCode), Payload: payload,
			}
		}
	default:
		different := CompareResponses(baseline.Body, attackBody, CompareMethod(comparison), threshold)
		if matcher.Negative {
			different = !different
		}
		if different {
			evidence := "len:" + intToString(len(attackBody)) + " vs " + intToString(len(baseline.Body))
			return MatchResult{
				Matched: true, Type: MatcherBoolean,
				Pattern: comparison, Evidence: evidence, Payload: payload,
			}
		}
	}

	return MatchResult{Matched: false}
}

func matchTimeBased(baseline *ExecutorResponse, attackBody string, attackCode int, attackDuration float64, matcher MatcherConfig, payload string) MatchResult {
	if baseline == nil {
		return MatchResult{Matched: false, Type: MatcherTimeBased, Payload: payload}
	}

	expectedDelay := matcher.Timeout
	if expectedDelay <= 0 {
		expectedDelay = 5
	}

	baselineSec := baseline.Duration.Seconds()
	attackSec := attackDuration

	diff := attackSec - baselineSec
	if diff < 0 {
		diff = 0
	}

	minDelay := float64(expectedDelay) * 0.8

	if diff >= minDelay {
		evidence := "delay:" + formatFloat(attackSec) + "s vs " + formatFloat(baselineSec) + "s"
		return MatchResult{
			Matched: true, Type: MatcherTimeBased,
			Pattern: "time_delay", Evidence: evidence, Payload: payload,
		}
	}

	return MatchResult{Matched: false}
}

func intToString(n int) string {
	return formatInt(n)
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	if neg {
		result = "-" + result
	}
	return result
}

func formatFloat(f float64) string {
	s := ""
	intPart := int(f)
	s += formatInt(intPart) + "."
	frac := int((f - float64(intPart)) * 100)
	if frac < 0 {
		frac = 0
	}
	if frac < 10 {
		s += "0"
	}
	s += formatInt(frac)
	return s
}

func matchPatterns(body string, matcher MatcherConfig, payload string) MatchResult {
	for _, pattern := range matcher.Patterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
			return MatchResult{
				Matched:  true,
				Type:     MatcherErrorBased,
				Pattern:  pattern,
				Evidence: extractEvidence(body, pattern, 100),
				Payload:  payload,
			}
		}
	}
	return MatchResult{Matched: false}
}
