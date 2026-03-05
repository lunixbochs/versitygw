package exa

// ExaAccess is the decoded exa1 access payload.
type ExaAccess struct {
	Version uint64 `cbor:"v"`
	Access  string `cbor:"a"`
	Secret  []byte `cbor:"s,omitempty"`
}
