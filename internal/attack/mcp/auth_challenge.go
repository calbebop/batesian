package mcp

import (
	"net/http"
	"strings"
)

type authChallenge struct {
	scheme           string
	resourceMetadata string
}

func authChallenges(headers http.Header) []authChallenge {
	var challenges []authChallenge
	for _, value := range headers.Values("WWW-Authenticate") {
		for _, segment := range challengeSegments(value) {
			scheme, params := challengeStart(segment)
			if scheme != "" {
				challenges = append(challenges, authChallenge{scheme: scheme})
			} else {
				params = segment
			}
			if len(challenges) == 0 {
				continue
			}
			if metadata, ok := challengeParam(params, "resource_metadata"); ok {
				challenges[len(challenges)-1].resourceMetadata = metadata
			}
		}
	}
	return challenges
}

func challengeSegments(value string) []string {
	var segments []string
	start := 0
	quoted := false
	escaped := false
	for i := 0; i < len(value); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && value[i] == '\\':
			escaped = true
		case value[i] == '"':
			quoted = !quoted
		case value[i] == ',' && !quoted:
			segments = append(segments, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	segments = append(segments, strings.TrimSpace(value[start:]))
	return segments
}

func challengeStart(segment string) (string, string) {
	segment = strings.TrimSpace(segment)
	i := 0
	for i < len(segment) && httpTokenByte(segment[i]) {
		i++
	}
	if i == 0 {
		return "", segment
	}
	if i == len(segment) {
		return segment, ""
	}
	if segment[i] != ' ' && segment[i] != '\t' {
		return "", segment
	}
	rest := strings.TrimSpace(segment[i:])
	if strings.HasPrefix(rest, "=") {
		return "", segment
	}
	return segment[:i], rest
}

func challengeParam(segment, name string) (string, bool) {
	key, value, ok := strings.Cut(segment, "=")
	if !ok || !strings.EqualFold(strings.TrimSpace(key), name) {
		return "", false
	}
	return challengeQuotedValue(strings.TrimSpace(value))
}

func challengeQuotedValue(value string) (string, bool) {
	if len(value) < 2 || value[0] != '"' {
		return "", false
	}
	var decoded strings.Builder
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			i++
			if i == len(value) {
				return "", false
			}
			decoded.WriteByte(value[i])
		case '"':
			return decoded.String(), strings.TrimSpace(value[i+1:]) == ""
		default:
			if value[i] < ' ' || value[i] == 0x7f {
				return "", false
			}
			decoded.WriteByte(value[i])
		}
	}
	return "", false
}

func httpTokenByte(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch))
}
