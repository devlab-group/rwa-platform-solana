package blockchain

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/rwa-platform/server/internal/dal/models"
	"github.com/rwa-platform/server/internal/dal/repository"
)

// programDataPrefix is the log-line prefix Anchor's `emit!` macro produces
// (via the `sol_log_data` syscall): "Program data: <base64>".
const programDataPrefix = "Program data: "

// sigPageLimit is the page size passed to getSignaturesForAddress, the
// maximum the RPC itself allows per call.
const sigPageLimit = 1000

// maxFetchPages bounds fetchNewSignatures to at most this many
// getSignaturesForAddress pages (i.e. maxFetchPages*sigPageLimit
// signatures) per pollProgram call. Steady-state
// polling — checkpoint close behind tip — never comes close to this cap;
// it only matters for a first sync or a program that has gone unpolled for
// a long time, where the backlog since the checkpoint is deep. In that
// case a single poll ingests only the newest maxFetchPages*sigPageLimit
// signatures rather than paging (and buffering) the program's entire
// history in one call; because getSignaturesForAddress pages BACKWARD from
// the tip, that newest slice sits at the TOP of the gap, not the bottom, so
// the poll cannot simply advance a forward checkpoint over it. Instead it
// records a backfill frontier on the checkpoint (see
// models.IndexerCheckpoint's backfill fields) and successive polls page
// downward from that frontier until the gap closes — the middle of a deep
// backlog is drained, never skipped.
const maxFetchPages = 10

// checkpointBatchSize bounds how many signatures pollProgram processes
// between checkpoint advances: ingestion is idempotent via
// ChainEventRepository.Exists, so advancing the checkpoint partway through
// a large batch is safe and keeps progress monotonic even if the process
// crashes or errors mid-batch, instead of an all-or-nothing checkpoint
// advance that only happens after the entire batch is ingested.
const checkpointBatchSize = 100

// programOrder is a fixed iteration order for the 5 emitting programs, so
// Poll's per-program scan sequence is deterministic across runs/tests.
var programOrder = []ProgramRole{RoleCompliance, RoleVault, RolePricing, RoleRedemption, RoleSupplyController}

// Indexer scans the 5 event-emitting Solana business programs by paging
// getSignaturesForAddress + getTransaction, decoding each transaction's
// "Program data:" log lines, and persisting them as models.ChainEvent —
// the Solana-source analog of evm/indexer.Indexer. It shares the same
// ChainEventRepository/IndexerCheckpointRepository, so every downstream
// projector is reused unchanged (see the frozen contract's addressing
// invariant: ChainEvent.Address is always the emitting program's base58
// program ID, verbatim).
//
// Unlike the EVM indexer there is no reorg handling: every RPC call is made
// at commitment (normally "finalized"), so results are, by construction,
// never subject to being rolled back.
type Indexer struct {
	src         Source
	checkpoints repository.IndexerCheckpointRepository
	events      repository.ChainEventRepository
	programIDs  map[ProgramRole]string
	chainID     int64
	commitment  string
	startSlot   uint64

	// silentSince records, per program, when it first polled successfully
	// while having ingested nothing at all. It exists purely so that state
	// gets SAID OUT LOUD: an RPC whose address->signature index no longer
	// covers a program answers getSignaturesForAddress with an empty array,
	// not an error, so pollProgram reads it as an ordinary idle poll. That is
	// indistinguishable from a healthy new deployment, and it is how a
	// deployment can sit for days with chain_events empty, every checkpoint at
	// lastBlock 0, and not one line in the log. Access is single-goroutine
	// (Poll is driven by one ticker), so no lock is needed.
	silentSince map[string]time.Time
}

// New constructs an Indexer. programIDs should have an entry for
// every role in {RoleCompliance, RoleVault, RolePricing, RoleRedemption,
// RoleSupplyController}; a missing/empty entry is skipped by Poll rather
// than erroring, so a deployment can wire only the programs it has
// addresses for. The transfer-hook program is deliberately never included
// here — it emits no events (see the frozen contract). startSlot bounds a
// program's FIRST sync (no checkpoint yet): getSignaturesForAddress with
// until="" walks all the way back through the program's entire history,
// which can include activity that predates this deployment (e.g. a reused
// program ID, or genesis/test activity); pollProgram skips ingesting any
// signature older than startSlot on first sync so that history is never
// replayed into this deployment's read model.
func New(src Source, checkpoints repository.IndexerCheckpointRepository, events repository.ChainEventRepository, programIDs map[ProgramRole]string, chainID int64, commitment string, startSlot uint64) *Indexer {
	return &Indexer{
		src: src, checkpoints: checkpoints, events: events,
		programIDs: programIDs, chainID: chainID, commitment: commitment, startSlot: startSlot,
		silentSince: map[string]time.Time{},
	}
}

// Poll performs one scan cycle across every configured program: for each,
// fetch signatures newer than its checkpoint, decode each transaction's
// logs oldest-first, and persist any newly-decoded events idempotently.
// Safe to call repeatedly (e.g. on a timer).
func (idx *Indexer) Poll(ctx context.Context) error {
	// Establishes a fresh view of the chain's current finalized slot before
	// scanning, mirroring the EVM indexer's head-read-first ordering.
	// Signature paging below is bounded by each program's own checkpoint
	// (`until`), not by this value, since getSignaturesForAddress at a
	// fixed commitment already only returns signatures that exist at that
	// commitment.
	if _, err := idx.src.GetSlot(ctx, idx.commitment); err != nil {
		return fmt.Errorf("blockchain: indexer: GetSlot: %w", err)
	}

	// Each program has its own independent checkpoint, so one program's
	// failure must not starve every later program in programOrder of its
	// own scan — compliance is first, and a persistent
	// compliance-side RPC error must not also stall vault/pricing/
	// redemption/supply-controller indexing. Every program is attempted;
	// errors are collected and joined into the return value instead of
	// returning on the first one.
	var errs []error
	for _, role := range programOrder {
		programID, ok := idx.programIDs[role]
		if !ok || programID == "" {
			continue
		}
		if err := idx.pollProgram(ctx, role, programID); err != nil {
			errs = append(errs, fmt.Errorf("blockchain: indexer: poll %s (%s): %w", role, programID, err))
		}
	}
	return errors.Join(errs...)
}

// pollProgram scans one program's new signatures and ingests their events.
//
// It runs in one of two modes, selected by whether the checkpoint carries a
// backfill frontier (BackfillCursor):
//
//   - Steady state (no frontier): page from the chain tip DOWN to the
//     checkpointed prefix (LastBlockHash), ingest oldest-first, and — if that
//     whole gap fit within the page cap — advance the contiguous checkpoint to
//     the tip. If it did NOT fit, the newest capped slice has been ingested but
//     sits at the top of the gap; freeze the prefix where it is and open a
//     backfill frontier so the next poll continues downward.
//   - Backfill (frontier set): resume paging DOWN from BackfillCursor toward
//     the frozen prefix. Each poll ingests the next capped slice and moves the
//     frontier further down; the poll that finally reaches the prefix promotes
//     the recorded high-water tip into the contiguous checkpoint and clears the
//     frontier — at which point [prefix, high-water] has been ingested with no
//     gap left in the middle.
func (idx *Indexer) pollProgram(ctx context.Context, role ProgramRole, programID string) (err error) {
	// Write the poll-health heartbeat on every SUCCESSFUL return of this
	// function, regardless of which of the several return
	// statements below actually fires — including a poll that ingested zero
	// signatures or only advanced the backfill frontier. Using a defer keyed
	// off the named return value means every existing `return ...`/`return
	// fmt.Errorf(...)` statement in this function already participates
	// correctly with no per-branch changes: a non-nil err skips the
	// heartbeat (this was not a successful poll), and a heartbeat write
	// failure itself becomes this call's error even though the actual
	// scan/ingest work already succeeded.
	defer func() {
		if err == nil {
			if hbErr := recordSuccessfulPoll(ctx, idx.checkpoints, idx.chainID, programID); hbErr != nil {
				err = fmt.Errorf("record poll heartbeat: %w", hbErr)
			}
		}
	}()

	cp, existed, err := loadProgramCheckpoint(ctx, idx.checkpoints, idx.chainID, programID)
	if err != nil {
		return err
	}

	// until is the lower bound of this poll's downward paging: the contiguous
	// prefix the checkpoint can already be trusted up to. It is "" until a
	// contiguous checkpoint has been established (a fresh program, or a first
	// sync still draining its initial backlog) — in which case paging walks
	// all the way back to the program's earliest signature, and the startSlot
	// filter (below) keeps pre-deployment history out of the read model.
	until := ""
	if existed {
		until = cp.LastBlockHash
	}
	backfilling := existed && cp.BackfillCursor != ""

	// before is where downward paging starts: the chain tip ("") in steady
	// state, or the recorded frontier when resuming a backfill.
	before := ""
	if backfilling {
		before = cp.BackfillCursor
	}

	sigs, reachedPrefix, err := idx.fetchNewSignatures(ctx, programID, before, until, cp.LastBlock)
	if err != nil {
		return fmt.Errorf("fetch signatures: %w", err)
	}

	if len(sigs) == 0 {
		// Nothing older than `before` remains. If we were backfilling, the
		// gap is empty — promote the high-water tip and clear the frontier;
		// otherwise there is simply nothing new to do.
		if backfilling {
			return idx.closeBackfill(ctx, programID, cp)
		}
		idx.noteSilentPoll(role, programID, cp.LastBlock == 0)
		return nil
	}
	idx.clearSilentPoll(programID)

	// The contiguous checkpoint may advance to every signature actually
	// OBSERVED, successful or failed — not just successfully-ingested ones. A
	// failed transaction never emitted any of its logged events (Anchor's
	// emit! runs inside program execution, which a failed transaction
	// reverts), so there is nothing to decode, but it is still a signature
	// this poll has now accounted for; leaving the checkpoint behind it would
	// only make every later poll re-fetch and re-skip the same failed
	// signature forever, and stall entirely if a program's newest activity is
	// a run of failures.
	//
	// contiguous is true only for a steady-state poll that paged the entire
	// gap in one shot: then the ingested slice is gap-free with the prefix and
	// the checkpoint can advance over it (in batches of checkpointBatchSize —
	// ingestion is idempotent via ChainEventRepository.Exists, so a checkpoint
	// that has moved partway through is still safe, and a crash partway through
	// a large backlog does not throw away all the progress already made).
	// A backfill poll, or a steady-state poll whose gap did not
	// fit the page cap, instead moves the frontier at the end (below): its
	// ingested slice sits at the TOP of a still-open gap, not contiguous with
	// the prefix, so the contiguous checkpoint must NOT move onto it yet.
	contiguous := !backfilling && reachedPrefix
	firstSync := until == ""
	sinceCheckpoint := 0
	for _, sig := range sigs {
		skip := sig.Err != nil
		if !skip && firstSync && idx.startSlot > 0 && sig.Slot < idx.startSlot {
			// First sync only (see New's doc comment): this signature
			// predates the deployment's startSlot, so it is not
			// part of this deployment's event stream. Still observed, so it
			// still counts toward the checkpoint advance — same reasoning as a
			// failed tx, above. The condition keys off an empty prefix rather
			// than a missing checkpoint row so it keeps applying across every
			// poll of a multi-poll first-sync backfill (during which the row
			// exists but LastBlockHash is still "").
			skip = true
		}
		if !skip {
			if err := idx.ingestTransaction(ctx, role, programID, sig); err != nil {
				return fmt.Errorf("ingest tx %s: %w", sig.Signature, err)
			}
		}

		if contiguous {
			sinceCheckpoint++
			if sinceCheckpoint >= checkpointBatchSize {
				if err := advanceProgramCheckpoint(ctx, idx.checkpoints, idx.chainID, programID, sig.Slot, sig.Signature); err != nil {
					return fmt.Errorf("advance checkpoint: %w", err)
				}
				sinceCheckpoint = 0
			}
		}
	}

	// sigs is oldest-first, so its last element is the newest observed this
	// poll and its first element is the oldest — the frontier for a further
	// downward page.
	newest := sigs[len(sigs)-1]
	oldest := sigs[0]

	switch {
	case contiguous:
		// Steady-state poll that drained the whole gap: the checkpoint is now
		// a gap-free prefix up to the tip.
		if sinceCheckpoint > 0 {
			if err := advanceProgramCheckpoint(ctx, idx.checkpoints, idx.chainID, programID, newest.Slot, newest.Signature); err != nil {
				return fmt.Errorf("advance checkpoint: %w", err)
			}
		}
		return nil
	case reachedPrefix:
		// Backfill poll that reached the frozen prefix: the gap is closed.
		// Everything from the prefix up through the high-water tip recorded
		// when the gap opened has now been ingested across the intervening
		// polls, so promote that tip into the contiguous checkpoint.
		return idx.closeBackfill(ctx, programID, cp)
	default:
		// The gap did not fit the page cap. The high-water tip is `newest`
		// when the gap first opens (a steady-state poll from the tip) and the
		// already-recorded target when continuing an existing backfill.
		targetSlot, targetSig := newest.Slot, newest.Signature
		if backfilling {
			targetSlot, targetSig = cp.BackfillTargetSlot, cp.BackfillTargetHash
		}
		if err := setBackfillFrontier(ctx, idx.checkpoints, idx.chainID, programID, cp.LastBlock, until, oldest.Signature, targetSlot, targetSig); err != nil {
			return fmt.Errorf("set backfill frontier: %w", err)
		}
		return nil
	}
}

// closeBackfill promotes the high-water tip recorded when a backlog's gap
// opened into the contiguous checkpoint and clears the backfill frontier. It
// is called once a backfill poll has paged down to the frozen prefix, so the
// whole [prefix, high-water] range is now ingested with no interior gap.
func (idx *Indexer) closeBackfill(ctx context.Context, programID string, cp *models.IndexerCheckpoint) error {
	if err := advanceProgramCheckpoint(ctx, idx.checkpoints, idx.chainID, programID, cp.BackfillTargetSlot, cp.BackfillTargetHash); err != nil {
		return fmt.Errorf("close backfill: %w", err)
	}
	return nil
}

// invokePrefix/successSuffix/failedInfix delimit the three log-framing line
// shapes the Solana runtime interleaves with a program's own "Program log:"/
// "Program data:" output: "Program <ID> invoke [<depth>]" (push),
// "Program <ID> success" (pop), "Program <ID> failed: <reason>" (pop).
const invokePrefix = "Program "

// minProgramIDLen/maxProgramIDLen bound the base58 encoding of a 32-byte
// Solana public key: 32 bytes base58-encodes to at least 32 characters (all
// leading-zero bytes) and at most 44.
const (
	minProgramIDLen = 32
	maxProgramIDLen = 44
)

// base58Alphabet is the Bitcoin/Solana base58 alphabet: every ASCII digit
// and letter except '0', 'O', 'I', and lowercase 'l' (dropped to avoid
// visual ambiguity). Notably it excludes ':' and ' ' — exactly what lets
// isPlausibleProgramID reject "Program log: ..."-derived text below.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// isBase58Byte is a byte-lookup table for base58Alphabet membership, built
// once at init.
var isBase58Byte = func() [256]bool {
	var t [256]bool
	for i := 0; i < len(base58Alphabet); i++ {
		t[base58Alphabet[i]] = true
	}
	return t
}()

// isPlausibleProgramID reports whether s could plausibly be a base58-encoded
// Solana program ID: base58-alphabet characters only, in the 32-44 length
// range a base58-encoded 32-byte public key falls in. This is a structural
// sanity check only — it can't (and doesn't try to) verify s names a real
// account — but it is exactly what turns parseInvokeLine/parsePopLine from
// a plain "Program " prefix match into something that can't be fooled by a
// program logging arbitrary text via msg!(), which the runtime renders as
// "Program log: <text>": text like "FAKE invoke [1]" or "something failed:
// x" contains a ':' and spaces, so it is never valid base58 and can never
// be mistaken for a push/pop of a real program ID. This is the first of
// three checks against a forged/malformed CPI-framing line; see
// parseInvokeLine's depth check and parsePopLine's stack-match check below
// for the other two.
func isPlausibleProgramID(s string) bool {
	if len(s) < minProgramIDLen || len(s) > maxProgramIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBase58Byte[s[i]] {
			return false
		}
	}
	return true
}

// parseInvokeLine reports the program ID and invocation depth pushed by an
// "Program <ID> invoke [<depth>]" line, and false for anything else. Beyond
// the prefix/suffix shape, a match additionally requires that ID pass
// isPlausibleProgramID and depth be a positive integer — the caller (see
// ingestTransaction) further requires depth to equal the current stack
// depth + 1, i.e. this line pushes at the position the runtime would
// actually place it (the second of the three CPI-framing checks — see
// isPlausibleProgramID's doc comment for the first).
func parseInvokeLine(line string) (programID string, depth int, ok bool) {
	rest, hasPrefix := strings.CutPrefix(line, invokePrefix)
	if !hasPrefix {
		return "", 0, false
	}
	id, tail, found := strings.Cut(rest, " invoke [")
	if !found {
		return "", 0, false
	}
	depthStr, hasSuffix := strings.CutSuffix(tail, "]")
	if !hasSuffix {
		return "", 0, false
	}
	n, err := strconv.Atoi(depthStr)
	if err != nil || n <= 0 {
		return "", 0, false
	}
	if !isPlausibleProgramID(id) {
		return "", 0, false
	}
	return id, n, true
}

// parsePopLine reports the program ID popped by a "Program <ID> success" or
// "Program <ID> failed: <reason>" line, and false for anything else
// (including the unrelated "Program log:"/"Program consumed"/"Program
// return:" lines, which never end in " success" or contain " failed: ", and
// including any line whose extracted ID fails isPlausibleProgramID — see
// parseInvokeLine). The caller (ingestTransaction) further requires the
// popped ID to equal the current top of the invocation stack before
// treating this as a genuine pop (the third of the three CPI-framing
// checks).
func parsePopLine(line string) (programID string, ok bool) {
	rest, hasPrefix := strings.CutPrefix(line, invokePrefix)
	if !hasPrefix {
		return "", false
	}
	if id, isSuccess := strings.CutSuffix(rest, " success"); isSuccess {
		if !isPlausibleProgramID(id) {
			return "", false
		}
		return id, true
	}
	if id, _, isFailed := strings.Cut(rest, " failed: "); isFailed {
		if !isPlausibleProgramID(id) {
			return "", false
		}
		return id, true
	}
	return "", false
}

// ingestTransaction fetches sig's full transaction and idempotently persists
// any event it finds that was ACTUALLY EMITTED by programID.
//
// getSignaturesForAddress(programID) returns every transaction that merely
// REFERENCES programID in its account list, not only transactions that
// invoke it — and Anchor event discriminators are public, so any other
// program a transaction happens to invoke can emit its own "Program data:"
// line carrying a discriminator+body that collides with one of programID's
// events. Trusting every "Program data:" line in the transaction as
// programID's own (as an earlier version of this function did) lets an
// unprivileged, permissionless actor forge events into the read model.
//
// The fix: reconstruct the CPI invocation stack from LogMessages' own
// "Program <ID> invoke [n]" / "Program <ID> success" / "Program <ID>
// failed: ..." framing lines (push/pop respectively) and attribute a
// "Program data:" line to whichever program is on TOP of that stack at the
// point the line appears — the program that is actually executing, exactly
// as the runtime itself would attribute it. A line is decoded as one of
// role's events ONLY when the top-of-stack program equals programID; every
// other "Program data:" line (a foreign CPI's own emission) is skipped
// without ever reaching Decode. This is derived entirely from the
// already-fetched LogMessages — no extra RPC call.
//
// LogIndex is assigned only to lines attributed to programID (in order),
// NOT to every "Program data:" line in the transaction — a foreign line
// skipped above never consumes a slot. Since attribution is a pure function
// of LogMessages (which never change for a given signature), this numbering
// is exactly as stable/deterministic across re-polls as the old "every data
// line" scheme was, so idempotency (keyed on LogIndex) still holds.
//
// A per-line Decode error (a recognized discriminator with a malformed
// body) is treated the same as "not a recognized event" — skipped, not
// propagated — so a single poisoned emission, even one genuinely emitted by
// programID, can never wedge the whole poll cycle; only a genuine
// RPC/transport failure (GetTransaction, Exists, Create) is fatal here.
func (idx *Indexer) ingestTransaction(ctx context.Context, role ProgramRole, programID string, sig SigInfo) error {
	tx, err := idx.src.GetTransaction(ctx, sig.Signature, idx.commitment)
	if err != nil {
		return fmt.Errorf("get transaction: %w", err)
	}
	if tx.Meta.Err != nil {
		// The signature list can lag or race a node's own view; treat a
		// transaction whose fetched meta reports failure the same as
		// sig.Err != nil above.
		return nil
	}

	var stack []string
	var logIndex uint
	for _, line := range tx.Meta.LogMessages {
		if id, depth, isInvoke := parseInvokeLine(line); isInvoke {
			if depth == len(stack)+1 {
				stack = append(stack, id)
			}
			// else: depth doesn't match where this would actually land on
			// the real invocation stack — not a genuine push here, so it's
			// ignored rather than corrupting stack state (the second
			// CPI-framing check).
			continue
		}
		if id, isPop := parsePopLine(line); isPop {
			if n := len(stack); n > 0 && stack[n-1] == id {
				stack = stack[:n-1]
			}
			// else: the popped id doesn't match the top of the stack —
			// not a genuine pop of the frame currently on top, so it's
			// ignored rather than popping the wrong frame (the third
			// CPI-framing check).
			continue
		}

		rest, isDataLine := strings.CutPrefix(line, programDataPrefix)
		if !isDataLine {
			continue // an ordinary "Program log:"/"consumed"/"return:" line, not a data emission
		}

		var emitter string
		if n := len(stack); n > 0 {
			emitter = stack[n-1]
		}
		if emitter != programID {
			// Not emitted by the program actually being scanned — e.g. a
			// foreign CPI's own data line (the forgery hazard described in
			// ingestTransaction's doc comment above). Skip WITHOUT
			// consuming a LogIndex slot: programID never emitted this line,
			// so it must never occupy a position in programID's numbering.
			continue
		}

		var (
			name string
			data map[string]any
			ok   bool
		)
		if payload, b64err := base64.StdEncoding.DecodeString(rest); b64err == nil {
			if n, d, decOK, decErr := Decode(role, payload); decErr == nil {
				name, data, ok = n, d, decOK
			}
			// decErr != nil (or a bad base64 payload) is treated exactly
			// like decOK == false: skip this one line (see above),
			// not a fatal poll error.
		}
		if ok {
			key := models.EventKey{ChainID: idx.chainID, Address: programID, TxHash: sig.Signature, LogIndex: logIndex}
			exists, err := idx.events.Exists(ctx, key)
			if err != nil {
				return fmt.Errorf("check existing event: %w", err)
			}
			if !exists {
				if err := idx.events.Create(ctx, &models.ChainEvent{
					ChainID: idx.chainID, Address: programID, TxHash: sig.Signature, LogIndex: logIndex,
					BlockNumber: tx.Slot, BlockHash: "", Name: name, Data: data, Removed: false,
					IndexedAt: time.Now().UTC(),
				}); err != nil {
					return fmt.Errorf("persist event: %w", err)
				}
			}
		}
		logIndex++
	}
	return nil
}

// fetchNewSignatures pages getSignaturesForAddress for program, walking
// backward via `before` (the chain tip when ""), until either a page proves
// paging has reached `until` (the program's contiguous-prefix signature,
// "" for a fresh program/first sync — see below), a page comes back
// short/empty with nothing further to prove, or maxFetchPages pages have
// been fetched (see maxFetchPages' doc comment). It reverses
// the accumulated pages to oldest-first — the order pollProgram must process
// them in — and reports reachedPrefix: whether paging is now KNOWN to have
// covered the entire remaining gap down to `until` (true), or whether a
// deeper gap may still be unread below the oldest signature returned
// (false), which pollProgram closes by resuming from that signature on a
// later poll.
//
// `until` is deliberately never forwarded to the RPC call itself (unlike
// an earlier version of this function). getSignaturesForAddress documents
// `until` as EXCLUSIVE, so even a fully compliant, fully-synced RPC would
// never return a signature at or below the checkpoint slot once `until` is
// passed to it — a short/empty page then looks IDENTICAL whether paging
// genuinely reached the prefix or this particular RPC node's retained
// history for the program simply ends above it (a non-archival,
// load-balanced, or freshly-resynced node, or one still catching up on a
// first sync). Trusting a short page as proof either way is exactly the
// permanent-data-loss hazard already fixed once, just with a different
// trigger this time: pollProgram would jump the contiguous checkpoint
// straight to the tip and silently skip everything in between.
//
// Instead paging always walks from `before` alone, and this function proves
// reaching the prefix directly from the DATA a page actually returns:
// untilSlot (pollProgram's cp.LastBlock) is the checkpoint's slot, and a
// page is trusted as having crossed the prefix only when it contains a
// signature that IS `until` or whose slot is <= untilSlot — positive
// evidence this RPC's history genuinely extends at or below the checkpoint.
// Everything in the page at or after that boundary is dropped (it is
// already-processed history); everything before it is newly observed
// activity and is kept.
//
// A short/empty page reached with no such evidence, having already
// observed some newer activity this call, means this RPC cannot serve the
// history needed to close the gap safely — this returns an error rather
// than a false reachedPrefix (per pollProgram's contiguous-checkpoint
// guard); the operator learns the RPC can't serve required history instead
// of the gap silently vanishing. Exhausting maxFetchPages on nothing but
// full pages, by contrast, is the ordinary deep-backlog case (reachedPrefix
// false, no error) — pollProgram opens/continues a backfill frontier and a
// later poll resumes downward.
//
// until == "" (no contiguous checkpoint yet — a fresh program, or a first
// sync still draining its initial backlog) has no prefix to prove: the
// startSlot filter, not this function, is what keeps pre-deployment history
// out of the read model on a first sync (see pollProgram/New's doc
// comments), so a short/empty page there is treated as reachedPrefix
// unconditionally, exactly as before this fix.
func (idx *Indexer) fetchNewSignatures(ctx context.Context, program, before, until string, untilSlot uint64) (sigs []SigInfo, reachedPrefix bool, err error) {
	var all []SigInfo
	reachedPrefix = false
	shortPage := false
	for page := 0; page < maxFetchPages; page++ {
		pageSigs, err := idx.src.GetSignaturesForAddress(ctx, program, sigPageLimit, before, "", idx.commitment)
		if err != nil {
			return nil, false, err
		}
		if len(pageSigs) == 0 {
			// until == "": nothing to prove (see doc comment). until != "":
			// nothing observed at all above an existing checkpoint means
			// the checkpoint IS the tip — unconditionally safe, since
			// there is nothing that could have been skipped.
			reachedPrefix = until == "" || len(all) == 0
			shortPage = true
			break
		}
		if until != "" {
			cut := -1
			for i, s := range pageSigs {
				if s.Signature == until || s.Slot <= untilSlot {
					cut = i
					break
				}
			}
			if cut >= 0 {
				all = append(all, pageSigs[:cut]...)
				reachedPrefix = true
				break
			}
		}
		all = append(all, pageSigs...)
		if len(pageSigs) < sigPageLimit {
			reachedPrefix = until == "" // see doc comment: no proof needed on a first sync
			shortPage = true
			break
		}
		before = pageSigs[len(pageSigs)-1].Signature
	}

	if !reachedPrefix && shortPage && until != "" && len(all) > 0 {
		return nil, false, fmt.Errorf("blockchain: indexer: %s: RPC paging ended above the checkpoint slot %d after observing %d newer signature(s), without ever proving it reached the prefix (no returned signature at or below that slot) — this RPC cannot serve the history needed to safely close the gap", program, untilSlot, len(all))
	}

	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, reachedPrefix, nil
}

// silentPollWarnAfter/silentPollRepeat bound how noisy the warning below gets:
// stay quiet long enough that an ordinary quiet period or a just-bootstrapped
// deployment never trips it, then repeat rarely enough to be a standing signal
// rather than log spam.
const (
	silentPollWarnAfter = 2 * time.Minute
	silentPollRepeat    = 30 * time.Minute
)

// noteSilentPoll warns when a program keeps polling successfully while never
// having ingested a single event.
//
// This is the observability gap behind a real incident: an RPC that has pruned
// its address->signature index returns an EMPTY ARRAY rather than an error, so
// every poll succeeds, the checkpoint never leaves lastBlock 0, chain_events
// stays empty, and every read model silently fails to populate — with nothing
// in the log to distinguish it from an idle chain. `opsctl indexer probe`
// diagnoses it; this makes it announce itself without being asked.
//
// It is a WARNING, never an error: a genuinely new deployment whose programs
// have not been used yet is in exactly this state legitimately, and refusing to
// poll (or failing readiness) over it would be wrong.
func (idx *Indexer) noteSilentPoll(role ProgramRole, programID string, neverIngested bool) {
	if !neverIngested {
		return
	}
	now := time.Now()
	since, seen := idx.silentSince[programID]
	if !seen {
		idx.silentSince[programID] = now
		return
	}
	quiet := now.Sub(since)
	if quiet < silentPollWarnAfter {
		return
	}
	log.Printf("blockchain: indexer: %s (%s) has polled successfully for %s but the RPC has returned NO signatures and nothing has ever been indexed — "+
		"if this program has on-chain activity, this RPC's address index does not cover it (pruned history, wrong program id, or wrong cluster). "+
		"Run `opsctl indexer probe` to confirm; every read model derived from this program stays empty until it is fixed.",
		role, programID, quiet.Round(time.Minute))
	// Re-arm so the next warning is silentPollRepeat away, not every tick.
	idx.silentSince[programID] = now.Add(silentPollRepeat - silentPollWarnAfter)
}

// clearSilentPoll resets the warning state once a program actually sees
// signatures again, so a transient outage does not leave a stale timer behind.
func (idx *Indexer) clearSilentPoll(programID string) {
	delete(idx.silentSince, programID)
}
