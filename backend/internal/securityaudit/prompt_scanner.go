package securityaudit

import (
	"sort"
)

func resultSeverity(decision EventDecision) int {
	switch decision {
	case EventCritical:
		return 3
	case EventFlag:
		return 2
	default:
		return 1
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func orderedScannerKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	remaining := make(map[string]struct{}, len(values))
	for key := range values {
		remaining[key] = struct{}{}
	}
	for _, scannerID := range AllScannerIDs {
		if _, ok := remaining[scannerID]; ok {
			result = append(result, scannerID)
			delete(remaining, scannerID)
		}
	}
	result = append(result, sortedKeys(remaining)...)
	return result
}
