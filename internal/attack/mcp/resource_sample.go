package mcp

import "sort"

const maxSampledResourceReads = 5

func listedResourceURIs(result map[string]interface{}) ([]string, bool) {
	if result == nil || result["resultType"] != "complete" {
		return nil, false
	}
	items, ok := result["resources"].([]interface{})
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			return nil, false
		}
		uri, ok := item["uri"].(string)
		if !ok || uri == "" {
			return nil, false
		}
		seen[uri] = true
	}
	uris := make([]string, 0, len(seen))
	for uri := range seen {
		uris = append(uris, uri)
	}
	sort.Strings(uris)
	return uris, true
}

func sampleResourceURIs(pages [][]string) []string {
	selected := make([]string, 0, maxSampledResourceReads)
	seen := map[string]bool{}
	maxLength := 0
	for _, page := range pages {
		if len(page) > maxLength {
			maxLength = len(page)
		}
	}
	for index := 0; index < maxLength && len(selected) < maxSampledResourceReads; index++ {
		for _, page := range pages {
			if index < len(page) && !seen[page[index]] {
				selected = append(selected, page[index])
				seen[page[index]] = true
				if len(selected) == maxSampledResourceReads {
					break
				}
			}
		}
	}
	return selected
}
