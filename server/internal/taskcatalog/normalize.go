package taskcatalog

import (
	"encoding/json"
	"math"
	"strconv"
)

func normalizeTaskProfileNumericDefaults(profile *TaskProfile) {
	if profile == nil {
		return
	}
	normalizeSchemaNumericDefaults(&profile.Schema)
}

func normalizeSchemaNumericDefaults(schema *TaskProfileSchema) {
	if schema == nil {
		return
	}
	for i := range schema.Parameters {
		if schema.Parameters[i].Type != "number" {
			continue
		}
		schema.Parameters[i].Default = normalizeNumberValue(schema.Parameters[i].Default)
	}

	if schema.Defaults == nil {
		return
	}
	for key, value := range schema.Defaults {
		param, ok := findParameter(schema.Parameters, key)
		if !ok || param.Type != "number" {
			continue
		}
		schema.Defaults[key] = normalizeNumberValue(value)
	}
}

func normalizeNumberValue(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		if uint64(v) <= math.MaxInt64 {
			return int64(v)
		}
		return value
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		if v <= math.MaxInt64 {
			return int64(v)
		}
		return value
	case float32:
		return normalizeNumberFloat64(float64(v))
	case float64:
		return normalizeNumberFloat64(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return normalizeNumberFloat64(f)
		}
		return value
	default:
		return value
	}
}

func normalizeNumberFloat64(v float64) any {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	if v == math.Trunc(v) && v >= math.MinInt64 && v <= math.MaxInt64 {
		return int64(v)
	}
	return json.Number(strconv.FormatFloat(v, 'f', -1, 64))
}
