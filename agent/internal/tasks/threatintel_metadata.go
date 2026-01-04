package tasks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/pkg/threatintel"
)

func appendThreatIntelMetadata(meta map[string]string, req TaskRequest) map[string]string {
	cfg := req.Config.ThreatIntel
	manager := req.ThreatIntel

	requested := cfg.Mode
	if requested == "" {
		requested = threatintel.ModeHybrid
	}
	effective := requested

	remoteSources, remoteConfigured := remoteSourcesFromConfig(cfg)
	remoteEnabled := false
	var noticeCodes []string
	noticeDetail := ""

	if manager != nil {
		effective = manager.Mode()
		remoteConfigured = manager.RemoteConfigured()
		remoteEnabled = manager.RemoteEnabled()
		remoteSources = manager.RemoteSources()
		noticeCodes = manager.NoticeCodes()
		noticeDetail = strings.Join(manager.Notices(), "; ")
	} else {
		switch requested {
		case threatintel.ModeServer:
			effective = threatintel.ModeServer
		case threatintel.ModeAuto:
			if remoteConfigured {
				effective = threatintel.ModeHybrid
			} else {
				effective = threatintel.ModeLocal
			}
		case threatintel.ModeHybrid:
			if !remoteConfigured {
				effective = threatintel.ModeLocal
			}
		default:
			// local/hybrid handled above; keep requested value.
		}
		remoteEnabled = effective == threatintel.ModeHybrid && remoteConfigured
	}

	if meta == nil {
		meta = make(map[string]string)
	}

	noticeCode := strings.TrimSpace(strings.Join(uniqueSortedNotEmpty(noticeCodes), ","))
	noticeDetail = strings.TrimSpace(noticeDetail)

	if noticeCode == "" {
		if reqCode := strings.TrimSpace(req.Metadata["threatintel.notice"]); reqCode != "" {
			noticeCode = reqCode
		}
	}
	if noticeCode == "" {
		if existing := strings.TrimSpace(meta["threatintel.notice"]); existing != "" {
			noticeCode = existing
		}
	}

	if noticeDetail == "" {
		if reqDetail := strings.TrimSpace(req.Metadata["threatintel.notice_detail"]); reqDetail != "" {
			noticeDetail = reqDetail
		}
	}
	if noticeDetail == "" {
		if existing := strings.TrimSpace(meta["threatintel.notice_detail"]); existing != "" {
			noticeDetail = existing
		}
	}

	if noticeCode == "" && noticeDetail != "" {
		noticeCode = threatintel.NoticeCodeUnknown
	}
	if noticeCode != "" && !isThreatIntelNoticeCode(noticeCode) {
		if noticeDetail == "" {
			noticeDetail = noticeCode
		} else {
			noticeDetail = strings.TrimSpace(noticeDetail + "; " + noticeCode)
		}
		noticeCode = threatintel.NoticeCodeUnknown
	}

	noticeDetail = threatintel.SanitizeNoticeDetail(noticeDetail, cfg)

	if effective == threatintel.ModeServer {
		noticeCode = threatintel.NoticeCodeServerMode
	}

	meta["threatintel.mode_requested"] = string(requested)
	meta["threatintel.mode_effective"] = string(effective)
	meta["threatintel.remote_configured"] = fmt.Sprintf("%t", remoteConfigured)
	meta["threatintel.remote_enabled"] = fmt.Sprintf("%t", remoteEnabled)
	meta["threatintel.remote_sources"] = strings.Join(remoteSources, ",")
	meta["threatintel.notice"] = noticeCode
	meta["threatintel.notice_detail"] = noticeDetail
	return meta
}

func remoteSourcesFromConfig(cfg threatintel.Config) ([]string, bool) {
	sources := make([]string, 0, 2)
	if strings.TrimSpace(cfg.OpenTIPAPIKey) != "" {
		sources = append(sources, "opentip")
	}
	if strings.TrimSpace(cfg.MetaDefenderAPIKey) != "" {
		sources = append(sources, "metadefender")
	}
	sort.Strings(sources)
	return sources, len(sources) > 0
}

func uniqueSortedNotEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isThreatIntelNoticeCode(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	parts := strings.Split(value, ",")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= '0' && r <= '9':
			case r == '_' || r == '-':
			default:
				return false
			}
		}
	}
	return true
}
