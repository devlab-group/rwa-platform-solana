package models

import "time"

// Lease is one distributed, fenced lease over a named resource
// (collection: leases). It backs multi-replica mode, where exactly one
// replica may run a given reconciler at a time — cmd/platform's
// runAsReconcilerLeader acquires a lease keyed "reconciler:<name>:<chainId>"
// on every tick, and the replica that loses simply no-ops that tick.
//
// Token is a strictly-monotonic fencing token, bumped on every successful
// Acquire (fresh grant or takeover) — see LeaseRepository.Acquire's doc
// comment. Deliberately never garbage collected by a TTL index (see the
// mongodb implementation's doc comment): an auto-deleted document would let
// Token silently reset, which would break the strict-monotonicity guarantee
// the whole fencing scheme depends on. The collection stays tiny regardless
// — one document per leased resource, not per operation.
type Lease struct {
	Key       string    `json:"key" bson:"_id"`
	HolderID  string    `json:"holderId" bson:"holderId"`
	Token     uint64    `json:"token" bson:"token"`
	ExpiresAt time.Time `json:"expiresAt" bson:"expiresAt"`
	UpdatedAt time.Time `json:"updatedAt" bson:"updatedAt"`
}
