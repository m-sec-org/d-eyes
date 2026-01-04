package threatintel

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

func (m *Manager) lookupRemoteHash(ctx context.Context, sha256 string, metadata map[string]string) ([]Finding, time.Duration) {
	if m == nil {
		return nil, 0
	}
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if len(sha256) != 64 {
		return nil, 0
	}
	findings := make([]Finding, 0)
	ttl := time.Duration(0)
	for _, name := range m.sortedRemoteNames() {
		provider := m.remote[name]
		if provider == nil {
			continue
		}
		if m.isRemotePaused(name, m.clock()) {
			continue
		}
		sem := m.remoteSem[name]
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return findings, ttl
			}
		}
		verdict, err := provider.LookupHash(ctx, sha256)
		if sem != nil {
			<-sem
		}
		if err != nil {
			m.handleRemoteError(name, err)
			continue
		}
		if verdict.TTL > 0 && (ttl == 0 || verdict.TTL < ttl) {
			ttl = verdict.TTL
		}
		if verdict.NotFound {
			continue
		}
		classification := strings.TrimSpace(verdict.Classification)
		confidence := strings.TrimSpace(verdict.Confidence)
		if classification == "" && confidence == "" {
			continue
		}
		details := map[string]string{
			"provider": name,
			"mode":     verdict.Mode,
		}
		if verdict.StatusCode > 0 {
			details["http_status"] = fmt.Sprintf("%d", verdict.StatusCode)
		}
		findings = append(findings, Finding{
			Indicator:      sha256,
			Kind:           IndicatorHash,
			Classification: classification,
			Confidence:     confidence,
			Source:         name,
			Details:        details,
			Context:        cloneMap(metadata),
			ObservedAt:     m.clock(),
		})
	}
	return findings, ttl
}

func (m *Manager) lookupRemoteFile(ctx context.Context, path string, sha256 string, metadata map[string]string) ([]Finding, time.Duration) {
	if m == nil {
		return nil, 0
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, 0
	}
	filename := filepath.Base(path)
	sha256 = strings.TrimSpace(strings.ToLower(sha256))
	if len(sha256) != 64 {
		return nil, 0
	}
	findings := make([]Finding, 0)
	ttl := time.Duration(0)

	for _, name := range m.sortedRemoteNames() {
		provider := m.remote[name]
		if provider == nil {
			continue
		}
		if m.isRemotePaused(name, m.clock()) {
			continue
		}
		sem := m.remoteSem[name]
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return findings, ttl
			}
		}

		verdict, err := provider.LookupHash(ctx, sha256)
		if err == nil && verdict.NotFound {
			verdict, err = provider.ScanFile(ctx, path, filename)
		}
		if sem != nil {
			<-sem
		}
		if err != nil {
			m.handleRemoteError(name, err)
			continue
		}
		if verdict.TTL > 0 && (ttl == 0 || verdict.TTL < ttl) {
			ttl = verdict.TTL
		}
		if verdict.NotFound {
			continue
		}
		classification := strings.TrimSpace(verdict.Classification)
		confidence := strings.TrimSpace(verdict.Confidence)
		if classification == "" && confidence == "" {
			continue
		}
		details := map[string]string{
			"provider": name,
			"mode":     verdict.Mode,
		}
		if verdict.StatusCode > 0 {
			details["http_status"] = fmt.Sprintf("%d", verdict.StatusCode)
		}
		findings = append(findings, Finding{
			Indicator:      sha256,
			Kind:           IndicatorHash,
			Classification: classification,
			Confidence:     confidence,
			Source:         name,
			Details:        details,
			Context:        cloneMap(metadata),
			ObservedAt:     m.clock(),
		})
	}
	return findings, ttl
}

func (m *Manager) isRemotePaused(provider string, now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	until, ok := m.remotePaused[provider]
	return ok && now.Before(until)
}

func (m *Manager) handleRemoteError(provider string, err error) {
	if m == nil || err == nil {
		return
	}
	var rerr *remoteError
	if errors.As(err, &rerr) {
		timeoutField := ""
		if m.cfg.HTTPTimeout > 0 {
			timeoutField = m.cfg.HTTPTimeout.String()
		}
		switch rerr.Kind {
		case remoteErrorKindRateLimit:
			pause := rerr.RetryAfter
			if pause <= 0 {
				pause = 30 * time.Second
			}
			m.pauseRemote(provider, pause)
			m.addNotice(NoticeCodeRemoteQuotaExceeded, "")
			m.addNotice(NoticeCodeRemotePaused, "")
			detail := FormatNoticeDetail(m.cfg, "远程查询触发限额，已暂停", NoticeField{Key: "provider", Value: provider}, NoticeField{Key: "status", Value: fmt.Sprintf("%d", rerr.StatusCode)}, NoticeField{Key: "retry_after", Value: pause.String()}, NoticeField{Key: "timeout", Value: timeoutField})
			m.addNotice("", detail)
		case remoteErrorKindTemporary:
			pause := rerr.RetryAfter
			if pause <= 0 {
				pause = 30 * time.Second
			}
			m.pauseRemote(provider, pause)
			m.addNotice(NoticeCodeProviderError, "")
			m.addNotice(NoticeCodeRemotePaused, "")
			status := ""
			if rerr.StatusCode > 0 {
				status = fmt.Sprintf("%d", rerr.StatusCode)
			}
			detail := FormatNoticeDetail(m.cfg, "远程查询暂不可用，已暂停", NoticeField{Key: "provider", Value: provider}, NoticeField{Key: "status", Value: status}, NoticeField{Key: "retry_after", Value: pause.String()}, NoticeField{Key: "timeout", Value: timeoutField})
			m.addNotice("", detail)
		default:
			m.addNotice(NoticeCodeProviderError, "")
			status := ""
			if rerr.StatusCode > 0 {
				status = fmt.Sprintf("%d", rerr.StatusCode)
			}
			detail := FormatNoticeDetail(m.cfg, "远程查询失败", NoticeField{Key: "provider", Value: provider}, NoticeField{Key: "status", Value: status}, NoticeField{Key: "timeout", Value: timeoutField})
			m.addNotice("", detail)
		}
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return
	}
	m.addNotice(NoticeCodeProviderError, "")
	timeoutField := ""
	if m.cfg.HTTPTimeout > 0 {
		timeoutField = m.cfg.HTTPTimeout.String()
	}
	detail := FormatNoticeDetail(m.cfg, "远程查询失败", NoticeField{Key: "provider", Value: provider}, NoticeField{Key: "timeout", Value: timeoutField})
	m.addNotice("", detail)
}
