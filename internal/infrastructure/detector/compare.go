package detector

type CompareMethod string

const (
	CompareLength     CompareMethod = "length"
	CompareBody       CompareMethod = "body"
	CompareSimilarity CompareMethod = "similarity"
)

func CompareResponses(baseline, attack string, method CompareMethod, threshold int) bool {
	switch method {
	case CompareLength:
		return compareLength(baseline, attack, threshold)
	case CompareBody:
		return compareBody(baseline, attack)
	case CompareSimilarity:
		return compareSimilarity(baseline, attack, threshold)
	default:
		return compareLength(baseline, attack, threshold)
	}
}

func compareLength(baseline, attack string, threshold int) bool {
	diff := len(attack) - len(baseline)
	if diff < 0 {
		diff = -diff
	}
	return diff >= threshold
}

func compareBody(baseline, attack string) bool {
	return baseline != attack
}

func compareSimilarity(baseline, attack string, thresholdPct int) bool {
	if len(baseline) == 0 && len(attack) == 0 {
		return false
	}
	if len(baseline) == 0 || len(attack) == 0 {
		return true
	}

	shorter := len(baseline)
	if len(attack) < shorter {
		shorter = len(attack)
	}
	longer := len(baseline)
	if len(attack) > longer {
		longer = len(attack)
	}

	ratio := (shorter * 100) / longer
	diffPct := 100 - ratio
	return diffPct >= thresholdPct
}

func GetBodyLength(body string) int {
	return len(body)
}
