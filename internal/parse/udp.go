package parse

import "errors"

var unmarshalUDPError = errors.New("insufficient bytes to unmarshal UDP")

type UDP struct {
	SourcePort      uint16
	DestinationPort uint16
}

func (p *UDP) domainName() string {
	return ""
}

func (p *UDP) unmarshal(payload []byte) error {
	return unmarshalUDPError // implement later
}
