// Package blockchain is the Solana JSON-RPC client, slot-based event
// indexer, and transaction assembly/signing used to observe and (for the
// one compliance hot-key exception) broadcast on-chain activity. This file
// covers the program IDL/event-decoding side: it ingests events emitted by
// the 5 event-emitting Solana business programs (compliance, vault,
// pricing, redemption, supply-controller — the transfer-hook program emits
// nothing, see the frozen cross-worker contract) into the same
// models.ChainEvent shape and repositories, so every downstream projector
// (redemption, sales, compliance) is reused unchanged.
package blockchain

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed idl/rwa_compliance.json
var complianceIDLJSON []byte

//go:embed idl/rwa_vault.json
var vaultIDLJSON []byte

//go:embed idl/rwa_pricing.json
var pricingIDLJSON []byte

//go:embed idl/rwa_redemption.json
var redemptionIDLJSON []byte

//go:embed idl/rwa_supply_controller.json
var supplyControllerIDLJSON []byte

// ProgramRole identifies which of the 5 event-emitting business programs a
// decoded "Program data:" log line belongs to. Dispatch MUST be by
// (role, discriminator) together, never discriminator alone: several
// discriminators (AdminChanged, AdminProposed, AdminTransferCancelled,
// RoleChanged, Finalized) are byte-identical across programs but carry
// different payloads/semantics — see the frozen contract's CRITICAL
// decoding rules.
type ProgramRole int

const (
	RoleCompliance ProgramRole = iota
	RoleVault
	RolePricing
	RoleRedemption
	RoleSupplyController
)

// String names a ProgramRole for error messages and test output.
func (r ProgramRole) String() string {
	switch r {
	case RoleCompliance:
		return "compliance"
	case RoleVault:
		return "vault"
	case RolePricing:
		return "pricing"
	case RoleRedemption:
		return "redemption"
	case RoleSupplyController:
		return "supply_controller"
	default:
		return fmt.Sprintf("ProgramRole(%d)", int(r))
	}
}

// FieldKind is one Borsh-decodable primitive shape this package supports —
// exactly the set the 5 business programs' event structs actually use.
type FieldKind int

const (
	KindPubkey FieldKind = iota
	KindU8
	KindU64
	KindI64
	KindBool
	KindBytes32
	KindBytes20
)

// Field is one event struct field, in Borsh (declaration) order.
type Field struct {
	Name string
	Kind FieldKind
}

// EventSchema is one program event's decode plan.
type EventSchema struct {
	Name   string
	Fields []Field
}

// idlFile mirrors just the subset of the Anchor IDL JSON shape this
// package needs: events (name + 8-byte discriminator) and the struct field
// lists ("types") those events reference by name.
type idlFile struct {
	Events []idlEvent `json:"events"`
	Types  []idlType  `json:"types"`
}

type idlEvent struct {
	Name string `json:"name"`
	// Discriminator arrives as a JSON array of numbers (e.g. [232,34,...]),
	// not a base64 string, so it can't be unmarshaled directly into []byte
	// (encoding/json treats []byte specially as base64).
	Discriminator []int `json:"discriminator"`
}

type idlType struct {
	Name string      `json:"name"`
	Type idlTypeBody `json:"type"`
}

type idlTypeBody struct {
	Kind   string         `json:"kind"`
	Fields []idlTypeField `json:"fields"`
}

type idlTypeField struct {
	Name string          `json:"name"`
	Type json.RawMessage `json:"type"`
}

// parseFieldKind decodes an IDL field "type" value, which is either a bare
// string ("pubkey", "u8", "u64", "i64", "bool") or a fixed-size array object
// ({"array":["u8",32]} / {"array":["u8",20]}) — the only shapes this
// package's supported events use.
func parseFieldKind(raw json.RawMessage) (FieldKind, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		switch name {
		case "pubkey":
			return KindPubkey, nil
		case "u8":
			return KindU8, nil
		case "u64":
			return KindU64, nil
		case "i64":
			return KindI64, nil
		case "bool":
			return KindBool, nil
		default:
			return 0, fmt.Errorf("blockchain: unsupported scalar field type %q", name)
		}
	}

	var arr struct {
		Array []json.RawMessage `json:"array"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr.Array) == 2 {
		var elemType string
		var size int
		if err := json.Unmarshal(arr.Array[0], &elemType); err == nil && elemType == "u8" {
			if err := json.Unmarshal(arr.Array[1], &size); err == nil {
				switch size {
				case 32:
					return KindBytes32, nil
				case 20:
					return KindBytes20, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("blockchain: unsupported field type %s", raw)
}

// parseIDL builds a discriminator -> EventSchema map from one embedded IDL
// file's "events" + "types" sections. Only types referenced by an event
// name are field-parsed — the IDL's "types" section also carries account
// structs (Registry, ComplianceRecord, ...) this package has no reason to
// (and, for some fields such as "docs"-only string arrays, cannot) decode.
func parseIDL(raw []byte) (map[[8]byte]EventSchema, error) {
	var f idlFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("blockchain: parse IDL: %w", err)
	}

	eventNames := make(map[string]bool, len(f.Events))
	for _, ev := range f.Events {
		eventNames[ev.Name] = true
	}

	fieldsByType := make(map[string][]Field, len(eventNames))
	for _, t := range f.Types {
		if !eventNames[t.Name] || t.Type.Kind != "struct" {
			continue
		}
		fields := make([]Field, 0, len(t.Type.Fields))
		for _, tf := range t.Type.Fields {
			kind, err := parseFieldKind(tf.Type)
			if err != nil {
				return nil, fmt.Errorf("blockchain: event %s field %s: %w", t.Name, tf.Name, err)
			}
			fields = append(fields, Field{Name: tf.Name, Kind: kind})
		}
		fieldsByType[t.Name] = fields
	}

	schemas := make(map[[8]byte]EventSchema, len(f.Events))
	for _, ev := range f.Events {
		if len(ev.Discriminator) != 8 {
			return nil, fmt.Errorf("blockchain: event %s: discriminator length %d, want 8", ev.Name, len(ev.Discriminator))
		}
		var disc [8]byte
		for i, b := range ev.Discriminator {
			disc[i] = byte(b)
		}
		fields, ok := fieldsByType[ev.Name]
		if !ok {
			return nil, fmt.Errorf("blockchain: event %s: no matching struct type definition", ev.Name)
		}
		schemas[disc] = EventSchema{Name: ev.Name, Fields: fields}
	}
	return schemas, nil
}

// registryInstance holds every embedded IDL's parsed event schemas, keyed
// by ProgramRole then by discriminator. Built once at package init; a
// malformed embedded IDL is a build-time bug, so it panics rather than
// forcing every caller to handle an error that can never occur outside
// development of this package itself.
var registryInstance = mustBuildRegistry()

func mustBuildRegistry() map[ProgramRole]map[[8]byte]EventSchema {
	sources := []struct {
		role ProgramRole
		json []byte
	}{
		{RoleCompliance, complianceIDLJSON},
		{RoleVault, vaultIDLJSON},
		{RolePricing, pricingIDLJSON},
		{RoleRedemption, redemptionIDLJSON},
		{RoleSupplyController, supplyControllerIDLJSON},
	}
	reg := make(map[ProgramRole]map[[8]byte]EventSchema, len(sources))
	for _, src := range sources {
		schemas, err := parseIDL(src.json)
		if err != nil {
			panic(fmt.Sprintf("blockchain: parse embedded IDL for %s: %v", src.role, err))
		}
		reg[src.role] = schemas
	}
	return reg
}
