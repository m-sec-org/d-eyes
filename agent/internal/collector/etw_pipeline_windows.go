//go:build windows

package collector

// ETWEventParser converts raw event records emitted by ETW into SystemEvent structures.
type ETWEventParser interface {
	Name() string
	SupportedProviders() []string
	ParseEvent(record *eventRecord) (*SystemEvent, error)
	Configure(cfg ParserConfig) error
}

// ETWParserManager coordinates parser registration and dispatch.
type ETWParserManager interface {
	RegisterParser(parser ETWEventParser)
	ParseEvent(providerGUID string, record *eventRecord) (*SystemEvent, error)
	UpdateConfig(cfg ParserConfig) error
}
