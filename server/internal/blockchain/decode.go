package blockchain

import "fmt"

// nameOverride disambiguates a Solana event Name that collides across
// programs into the distinct ChainEvent.Name the frozen contract requires:
// both compliance and supply-controller emit "Finalized" with unrelated
// payloads/semantics, so each is renamed to a program-specific
// ChainEvent.Name W3's projectors can dispatch on unambiguously.
var nameOverride = map[ProgramRole]map[string]string{
	RoleCompliance:       {"Finalized": "ComplianceFinalized"},
	RoleSupplyController: {"Finalized": "SupplyFinalized"},
}

// fieldRename maps a Borsh snake_case struct field name to the camelCase
// ChainEvent.Data key the frozen contract specifies. Applied uniformly:
// the same snake_case name always maps to the same camelCase key
// everywhere it appears across every program/event. A name absent from
// this map (already a single word, e.g. "role", "by", "account", "amount")
// is used as-is.
var fieldRename = map[string]string{
	"new_admin":            "newAdmin",
	"new_value":            "newValue",
	"new_status":           "newStatus",
	"new_price":            "newPrice",
	"new_pricer":           "newPricer",
	"new_auditor":          "newAuditor",
	"previous_status":      "previousStatus",
	"previous_valid_until": "previousValidUntil",
	"new_valid_until":      "newValidUntil",
	"rwa_amount":           "rwaAmount",
	"quote_amount":         "quoteAmount",
	"created_at":           "createdAt",
	"reason_code":          "reasonCode",
	"token_amount":         "tokenAmount",
	"record_key":           "recordKey",
	"metadata_digest":      "metadataDigest",
	"operation_id":         "operationId",
}

// Decode splits payload into its 8-byte Anchor event discriminator and
// Borsh-encoded body, looks up the schema for (role, discriminator) —
// dispatch MUST include role, since several discriminators are identical
// across programs but carry different payloads (see the frozen contract) —
// and decodes the body into the ChainEvent.Name/Data the frozen contract
// specifies.
//
// ok=false (with err=nil) means payload is not a genuine event of this
// role — its discriminator is unrecognized (e.g. an unrelated CPI's own
// "Program data:" log, or a garbage/truncated line), or its discriminator
// matched but the body left trailing bytes unconsumed (a colliding-
// discriminator spoof — no genuine Anchor event has a tail) — so the
// caller (Indexer.ingestTransaction) can skip it rather than treating it as
// a hard decode failure.
func Decode(role ProgramRole, payload []byte) (name string, data map[string]any, ok bool, err error) {
	if len(payload) < 8 {
		return "", nil, false, nil
	}
	schemas, known := registryInstance[role]
	if !known {
		return "", nil, false, fmt.Errorf("blockchain: decode: unknown program role %v", role)
	}
	var disc [8]byte
	copy(disc[:], payload[:8])
	schema, found := schemas[disc]
	if !found {
		return "", nil, false, nil
	}

	r := newBorshReader(payload[8:])
	out := make(map[string]any, len(schema.Fields))
	for _, f := range schema.Fields {
		key := f.Name
		if renamed, ok := fieldRename[key]; ok {
			key = renamed
		}
		var (
			v    any
			derr error
		)
		switch f.Kind {
		case KindPubkey:
			v, derr = r.pubkey()
		case KindU8:
			var n uint64
			n, derr = r.u8()
			v = uint(n)
		case KindU64:
			v, derr = r.u64String()
		case KindI64:
			v, derr = r.i64String()
		case KindBool:
			v, derr = r.boolean()
		case KindBytes32:
			v, derr = r.hexBytes(32)
		case KindBytes20:
			v, derr = r.hexBytes(20)
		default:
			derr = fmt.Errorf("blockchain: decode %s.%s: unsupported field kind %d", schema.Name, f.Name, f.Kind)
		}
		if derr != nil {
			return "", nil, false, fmt.Errorf("blockchain: decode %s.%s: %w", schema.Name, f.Name, derr)
		}
		out[key] = v
	}
	if r.pos != len(r.buf) {
		// A genuine Anchor event's Borsh body is exactly the sum of its
		// declared fields' widths — no trailing bytes. Leftover bytes mean
		// either a schema/wire mismatch or a forged line whose
		// discriminator happens to collide with a real one:
		// ok=false lets the caller skip it like any other non-match, cheap
		// defense-in-depth against a colliding-discriminator spoof.
		return "", nil, false, nil
	}

	finalName := schema.Name
	if overrides, ok := nameOverride[role]; ok {
		if renamed, ok := overrides[schema.Name]; ok {
			finalName = renamed
		}
	}
	return finalName, out, true, nil
}
