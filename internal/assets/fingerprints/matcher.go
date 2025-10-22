package fingerprints

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// ServiceMatchResult represents the outcome of service fingerprinting.
type ServiceMatchResult struct {
	Name       string
	Confidence float64
}

// ServiceEvidence captures information gathered during banner probing.
type ServiceEvidence struct {
	Port          int
	Protocol      string
	Banner        string
	RawBanner     []byte
	TLSCommonName string
	Metadata      map[string]string
}

// MatchService evaluates fingerprints against banner/port/protocol info.
func MatchService(fps []ServiceFingerprint, evidence ServiceEvidence) ServiceMatchResult {
	best := ServiceMatchResult{}
	protocol := strings.ToLower(evidence.Protocol)
	if protocol == "" {
		protocol = "tcp"
	}

	for _, fp := range fps {
		score := 0.0

		if fp.Match.Protocol == "" || strings.EqualFold(fp.Match.Protocol, protocol) {
			score += 2
		} else {
			continue
		}

		if len(fp.Match.Ports) == 0 {
			score += 1
		} else {
			for _, p := range fp.Match.Ports {
				if p == evidence.Port {
					score += 4
					break
				}
			}
		}

		for _, pattern := range fp.Match.Patterns {
			if evaluatePattern(pattern, evidence) {
				score += 3
			}
		}

		if score > best.Confidence {
			best = ServiceMatchResult{Name: fp.Name, Confidence: score}
		}
	}
	return best
}

func evaluatePattern(pattern Pattern, evidence ServiceEvidence) bool {
	value := pattern.Value
	switch strings.ToLower(pattern.Type) {
	case "regex":
		return matchRegex(value, evidence.Banner)
	case "prefix", "banner_prefix":
		return strings.HasPrefix(strings.ToLower(evidence.Banner), strings.ToLower(value))
	case "contains", "banner_contains":
		return strings.Contains(strings.ToLower(evidence.Banner), strings.ToLower(value))
	case "binary_prefix":
		raw := evidence.RawBanner
		if len(raw) == 0 {
			raw = []byte(evidence.Banner)
		}
		return bytes.HasPrefix(raw, decodeEscapes(value))
	case "binary_contains":
		raw := evidence.RawBanner
		if len(raw) == 0 {
			raw = []byte(evidence.Banner)
		}
		return bytes.Contains(raw, decodeEscapes(value))
	case "tls_cn":
		if evidence.TLSCommonName == "" {
			return false
		}
		return matchRegex(value, evidence.TLSCommonName)
	case "json_field":
		return hasJSONField(evidence.Banner, value)
	case "dns_response":
		return metadataContains(evidence.Metadata, "dns_response", value)
	case "ntp_response":
		return metadataContains(evidence.Metadata, "ntp_response", value)
	default:
		return false
	}
}

func matchRegex(pattern, input string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(input)
}

func hasJSONField(payload, fieldPath string) bool {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return false
	}
	var data interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		// not a JSON payload
		return false
	}
	segments := strings.Split(fieldPath, ".")
	current := data
	for _, segment := range segments {
		m, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		value, ok := m[segment]
		if !ok {
			return false
		}
		current = value
	}
	return true
}

func metadataContains(meta map[string]string, key, value string) bool {
	if len(meta) == 0 {
		return false
	}
	content, ok := meta[key]
	if !ok {
		return false
	}
	if value == "" {
		return content != ""
	}
	return strings.Contains(strings.ToLower(content), strings.ToLower(value))
}

func decodeEscapes(val string) []byte {
	if val == "" {
		return nil
	}
	result := make([]byte, 0, len(val))
	for i := 0; i < len(val); {
		if val[i] == '\\' {
			if i+1 < len(val) {
				switch val[i+1] {
				case 'x', 'X':
					if i+3 < len(val) {
						if v, err := strconv.ParseUint(val[i+2:i+4], 16, 8); err == nil {
							result = append(result, byte(v))
							i += 4
							continue
						}
					}
				case 'n':
					result = append(result, '\n')
					i += 2
					continue
				case 'r':
					result = append(result, '\r')
					i += 2
					continue
				case 't':
					result = append(result, '\t')
					i += 2
					continue
				case '\\':
					result = append(result, '\\')
					i += 2
					continue
				default:
					result = append(result, val[i+1])
					i += 2
					continue
				}
			}
			// dangling backslash, skip it
			i++
			continue
		}
		result = append(result, val[i])
		i++
	}
	return result
}

// OSContext describes host characteristics used for OS detection.
type OSContext struct {
	TTL      int
	Services map[int]string
	Banners  map[string]string
}

// MatchOS returns the best matching OS fingerprint.
func MatchOS(fps []OSFingerprint, ctx OSContext) (string, float64) {
	bestName := ""
	bestScore := 0.0
	for _, fp := range fps {
		score := 0.0
		if len(fp.Heuristics.TTLRange) == 2 && ctx.TTL > 0 {
			if ctx.TTL >= fp.Heuristics.TTLRange[0] && ctx.TTL <= fp.Heuristics.TTLRange[1] {
				score += 4
			}
		}
		for _, svc := range fp.Heuristics.Services {
			if name, ok := ctx.Services[svc.Port]; ok {
				if svc.Service == "" || strings.EqualFold(name, svc.Service) {
					score += 3
				}
			}
		}
		for _, banner := range fp.Heuristics.Banners {
			value := strings.ToLower(banner.Contains)
			if svcBanner, ok := ctx.Banners[strings.ToLower(banner.Service)]; ok {
				if strings.Contains(strings.ToLower(svcBanner), value) {
					score += 3
				}
			}
		}
		if score > bestScore {
			bestScore = score
			bestName = fp.OS
		}
	}
	return bestName, bestScore
}
