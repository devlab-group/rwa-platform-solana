package blockchain

import (
	"encoding/base64"
	"strings"
)

// ProbeDecodableEvents reports which of a transaction's "Program data:" log
// lines decode as events for role, and how many do not.
//
// It is diagnostic-only (cmd/opsctl's `indexer probe`) and deliberately does
// NOT reproduce ingestTransaction's CPI emitter-attribution: it answers the
// narrower question "does this role's schema recognise the event payloads
// present in this transaction at all?", which is what distinguishes an IDL /
// schema drift from an RPC or addressing problem. Attribution is the indexer's
// job and is tested separately.
//
// Returns the decoded event names in log order, plus a count of program-data
// lines that did not decode for this role — which for a transaction that CPIs
// into other programs is entirely normal, since those lines belong to them.
func ProbeDecodableEvents(role ProgramRole, logs []string) (names []string, undecodable int) {
	for _, line := range logs {
		rest, ok := strings.CutPrefix(line, programDataPrefix)
		if !ok {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			undecodable++
			continue
		}
		name, _, decoded, err := Decode(role, payload)
		if err != nil || !decoded {
			undecodable++
			continue
		}
		names = append(names, name)
	}
	return names, undecodable
}
