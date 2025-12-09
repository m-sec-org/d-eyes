package eventing

import (
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// ApplyRetentionMetadata stamps retention cutoff timestamps onto an event record.
func ApplyRetentionMetadata(ret config.EventRetentionConfig, rec *model.SystemEventRecord) {
	if rec == nil {
		return
	}
	if rec.Metadata == nil {
		rec.Metadata = make(map[string]string)
	}
	base := rec.ReceivedAt
	if base.IsZero() {
		base = time.Now().UTC()
		rec.ReceivedAt = base
	}
	if dur := ret.Hot; dur > 0 {
		rec.Metadata["retention.hot_until"] = base.Add(dur).Format(time.RFC3339Nano)
		base = base.Add(dur)
	}
	if dur := ret.Warm; dur > 0 {
		rec.Metadata["retention.warm_until"] = base.Add(dur).Format(time.RFC3339Nano)
		base = base.Add(dur)
	}
	if dur := ret.Cold; dur > 0 {
		rec.Metadata["retention.cold_until"] = base.Add(dur).Format(time.RFC3339Nano)
	}
}
