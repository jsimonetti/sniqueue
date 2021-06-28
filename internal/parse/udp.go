package parse

type UDP struct {
	SourcePort      uint16
	DestinationPort uint16
}

func (p *UDP) domainName() string {
	return ""
}

func (p *UDP) unmarshal(payload []byte) error {
	return unmarshalInsufficientError // implement later
}
