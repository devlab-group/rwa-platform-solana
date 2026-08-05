package blockchain

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// --- layout cross-check against the checked-in IDLs -------------------------

// accountLayout is the field sequence ReadBaseline's decoder assumes for one
// account, transcribed from the reads in config_accounts.go — names and Anchor
// type strings, in wire order.
type accountLayout struct {
	idl []byte
	// idlName is how the IDL names the account. Anchor module-qualifies a name
	// that collides across programs, so the supply-controller's is
	// "rwa_supply_controller::Config" while the vault's is plain "Config" —
	// even though both are a Rust struct called `Config` and therefore share a
	// discriminator.
	idlName string
	// goName is what config_accounts.go passes to accountDiscriminator, i.e.
	// the bare Rust struct name. The test asserts this actually reproduces the
	// IDL's declared discriminator.
	goName string
	fields []string // "name:type", in wire order
}

// TestBaselineLayoutsMatchIDL is the test that gives the decoders their
// meaning. Borsh carries no field names on the wire, so a decoder that skips
// one field too few or too many silently reads every LATER field off the wrong
// bytes — and still "succeeds", handing the security projection plausible
// garbage (a treasury that is really half a mint, a price that is really a
// bump byte). A hand-written fixture cannot catch that, because the fixture
// and the decoder would share the same wrong assumption.
//
// The checked-in Anchor IDLs are an independent source of truth: they are
// generated from the Rust structs by `anchor build`, not written by hand here.
// Asserting the decoder's assumed field sequence equals the IDL's declared one
// catches a reordered, inserted, removed, or retyped field the next time the
// programs change, at `go test` time rather than in production.
func TestBaselineLayoutsMatchIDL(t *testing.T) {
	layouts := map[string]accountLayout{
		"supply-controller Config": {supplyControllerIDLJSON, "rwa_supply_controller::Config", "Config", []string{
			"admin:pubkey", "pending_admin:pubkey", "auditor_eth:[u8;20]",
		}},
		"vault Config": {vaultIDLJSON, "Config", "Config", []string{
			"admin:pubkey", "pending_admin:pubkey", "treasurer:pubkey", "treasury:pubkey",
			"supply_controller:pubkey", "rwa_mint:pubkey", "quote_mint:pubkey",
			"quote_decimals:u8", "strategy:pubkey", "registry:pubkey",
		}},
		"pricing Strategy": {pricingIDLJSON, "Strategy", "Strategy", []string{
			"admin:pubkey", "pending_admin:pubkey", "pricer:pubkey",
			"token_decimals:u8", "purchase_price:u64", "redemption_price:u64",
		}},
		"compliance Registry": {complianceIDLJSON, "Registry", "Registry", []string{
			"admin:pubkey", "pending_admin:pubkey", "compliance_authority:pubkey",
			"pauser:pubkey", "vault:pubkey", "escrow:pubkey", "supply_controller:pubkey",
			"rwa_mint:pubkey", "system_set:bool", "paused:bool", "finalized:bool",
		}},
		"redemption Config": {redemptionIDLJSON, "Config", "Config", []string{
			"admin:pubkey", "pending_admin:pubkey", "treasurer:pubkey", "redemption_manager:pubkey",
		}},
	}

	for name, want := range layouts {
		t.Run(name, func(t *testing.T) {
			// The discriminator our decoder computes from the bare struct
			// name must equal the one anchor put in the IDL.
			if got, wantDisc := accountDiscriminator(want.goName), idlAccountDiscriminator(t, want.idl, want.idlName); got != wantDisc {
				t.Errorf("accountDiscriminator(%q) = %v, IDL declares %v", want.goName, got, wantDisc)
			}
			got := idlAccountFields(t, want.idl, want.idlName)
			// The decoder reads a PREFIX of each account (it stops once it has
			// what it needs), so compare only that prefix — but require the
			// IDL to actually have at least that many fields.
			if len(got) < len(want.fields) {
				t.Fatalf("IDL declares %d fields, decoder reads %d", len(got), len(want.fields))
			}
			for i, w := range want.fields {
				if got[i] != w {
					t.Errorf("field %d: IDL has %q, decoder assumes %q", i, got[i], w)
				}
			}
		})
	}
}

// idlAccountDiscriminator returns the 8-byte discriminator anchor recorded for
// an account in the IDL — generated from the Rust source, so an independent
// check on accountDiscriminator's sha256("account:"+Name) derivation.
func idlAccountDiscriminator(t *testing.T, raw []byte, account string) [8]byte {
	t.Helper()
	var doc struct {
		Accounts []struct {
			Name          string `json:"name"`
			Discriminator []byte `json:"discriminator"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing IDL: %v", err)
	}
	for _, a := range doc.Accounts {
		if a.Name != account {
			continue
		}
		if len(a.Discriminator) != 8 {
			t.Fatalf("IDL discriminator for %q is %d bytes, want 8", account, len(a.Discriminator))
		}
		return [8]byte(a.Discriminator)
	}
	t.Fatalf("IDL declares no account %q", account)
	return [8]byte{}
}

// idlAccountFields returns an IDL account struct's fields as "name:type",
// in declaration (== Borsh wire) order.
func idlAccountFields(t *testing.T, raw []byte, account string) []string {
	t.Helper()
	var doc struct {
		Types []struct {
			Name string `json:"name"`
			Type struct {
				Kind   string `json:"kind"`
				Fields []struct {
					Name string          `json:"name"`
					Type json.RawMessage `json:"type"`
				} `json:"fields"`
			} `json:"type"`
		} `json:"types"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing IDL: %v", err)
	}
	for _, ty := range doc.Types {
		if ty.Name != account {
			continue
		}
		out := make([]string, 0, len(ty.Type.Fields))
		for _, f := range ty.Type.Fields {
			out = append(out, f.Name+":"+idlTypeString(f.Type))
		}
		return out
	}
	t.Fatalf("IDL has no account type %q", account)
	return nil
}

// idlTypeString renders an IDL type node: a bare string ("pubkey", "u64") or
// a fixed array object ({"array":["u8",20]}).
func idlTypeString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var arr struct {
		Array []json.RawMessage `json:"array"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr.Array) == 2 {
		var elem string
		var n int
		_ = json.Unmarshal(arr.Array[0], &elem)
		_ = json.Unmarshal(arr.Array[1], &n)
		return fmt.Sprintf("[%s;%d]", elem, n)
	}
	return string(raw)
}

// --- end-to-end decode over a fake RPC --------------------------------------

const (
	fxSupplyProgram     = "SuppLyCtR1111111111111111111111111111111111"
	fxVaultProgram      = "VauLT1111111111111111111111111111111111111"
	fxPricingProgram    = "PriciNg111111111111111111111111111111111111"
	fxComplianceProgram = "CompLiance111111111111111111111111111111111"
	fxRedemptionProgram = "REdempT10n1111111111111111111111111111111"
)

// fxKey returns a deterministic, DISTINCT 32-byte base58 pubkey per label.
//
// Distinctness is the point. The fixtures below give every field its own key —
// including the ones the decoder skips — so a decoder that reads one field too
// early or too late lands on a different key and the assertion fails. Reusing
// a single filler pubkey across several skipped fields would mask exactly the
// off-by-one-field shift these tests exist to catch.
func fxKey(label string) string {
	h := sha256.Sum256([]byte("fixture:" + label))
	return base58.Encode(h[:])
}

// Addresses and role holders, each its own key.
var (
	fxSupplyCfgAddr  = fxKey("supply-config")
	fxVaultCfgAddr   = fxKey("vault-config")
	fxStrategyAddr   = fxKey("strategy")
	fxRegistryAddr   = fxKey("registry")
	fxEscrowAddr     = fxKey("escrow")
	fxTreasury       = fxKey("treasury")
	fxTreasurer      = fxKey("treasurer")
	fxPricer         = fxKey("pricer")
	fxComplianceAuth = fxKey("compliance-authority")
	fxPauser         = fxKey("pauser")
	fxRedManager     = fxKey("redemption-manager")
)

// acctBuilder assembles an Anchor account body: 8-byte discriminator for
// typeName followed by Borsh fields appended in declaration order.
type acctBuilder struct{ b []byte }

func newAcct(typeName string) *acctBuilder {
	d := accountDiscriminator(typeName)
	return &acctBuilder{b: append([]byte{}, d[:]...)}
}
func (a *acctBuilder) pubkey(t *testing.T, s string) *acctBuilder {
	t.Helper()
	raw, err := base58.Decode(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("fixture pubkey %q is not 32 bytes: %v", s, err)
	}
	a.b = append(a.b, raw...)
	return a
}
func (a *acctBuilder) zeroPubkey() *acctBuilder { a.b = append(a.b, make([]byte, 32)...); return a }
func (a *acctBuilder) bytesN(n int, fill byte) *acctBuilder {
	for i := 0; i < n; i++ {
		a.b = append(a.b, fill+byte(i))
	}
	return a
}
func (a *acctBuilder) u8(v byte) *acctBuilder { a.b = append(a.b, v); return a }
func (a *acctBuilder) boolean(v bool) *acctBuilder {
	var b byte
	if v {
		b = 1
	}
	a.b = append(a.b, b)
	return a
}
func (a *acctBuilder) u64(v uint64) *acctBuilder {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	a.b = append(a.b, buf[:]...)
	return a
}

// fakeAccountServer answers getAccountInfo per address from a table.
func fakeAccountServer(t *testing.T, accounts map[string]struct {
	data  []byte
	owner string
}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		_ = json.Unmarshal(body, &req)
		var addr string
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params[0], &addr)
		}
		w.Header().Set("Content-Type", "application/json")
		acct, ok := accounts[addr]
		if !ok {
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"value":null}}`)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"value":{"data":[%q,"base64"],"owner":%q}}}`,
			base64.StdEncoding.EncodeToString(acct.data), acct.owner)
	}))
}

type acct = struct {
	data  []byte
	owner string
}

// fullDeployment builds every config account of a healthy, bootstrapped
// deployment, wired so ReadBaseline's on-chain address walk works: the vault
// Config names the strategy and registry, and the registry names the escrow.
func fullDeployment(t *testing.T) map[string]acct {
	t.Helper()
	supply := newAcct("Config").
		pubkey(t, fxKey("supply.admin")).
		pubkey(t, fxKey("supply.pending_admin")).
		bytesN(20, 0xA0). // auditor_eth
		pubkey(t, fxKey("supply.token_mint")).
		pubkey(t, fxVaultCfgAddr). // vault
		pubkey(t, fxRegistryAddr). // registry
		bytesN(32, 0x10).          // profile_digest
		bytesN(32, 0x40).          // cluster
		boolean(true).             // finalized
		u8(255)                    // bump

	vault := newAcct("Config").
		pubkey(t, fxKey("vault.admin")).
		pubkey(t, fxKey("vault.pending_admin")).
		pubkey(t, fxTreasurer).
		pubkey(t, fxTreasury).
		pubkey(t, fxSupplyCfgAddr). // supply_controller
		pubkey(t, fxKey("vault.rwa_mint")).
		pubkey(t, fxKey("vault.quote_mint")).
		u8(6). // quote_decimals
		pubkey(t, fxStrategyAddr).
		pubkey(t, fxRegistryAddr).
		u8(254) // bump

	strategy := newAcct("Strategy").
		pubkey(t, fxKey("pricing.admin")).
		pubkey(t, fxKey("pricing.pending_admin")).
		pubkey(t, fxPricer).
		u8(6).          // token_decimals
		u64(2_000_000). // purchase_price
		u64(1_950_000). // redemption_price
		u8(253)         // bump

	registry := newAcct("Registry").
		pubkey(t, fxKey("registry.admin")).
		pubkey(t, fxKey("registry.pending_admin")).
		pubkey(t, fxComplianceAuth).
		pubkey(t, fxPauser).
		pubkey(t, fxVaultCfgAddr).  // vault
		pubkey(t, fxEscrowAddr).    // escrow
		pubkey(t, fxSupplyCfgAddr). // supply_controller
		pubkey(t, fxKey("registry.rwa_mint")).
		boolean(true). // system_set
		boolean(true). // paused
		boolean(true). // finalized
		u8(252)

	redemption := newAcct("Config").
		pubkey(t, fxKey("redemption.admin")).
		pubkey(t, fxKey("redemption.pending_admin")).
		pubkey(t, fxKey("redemption.treasurer")).
		pubkey(t, fxRedManager)

	return map[string]acct{
		fxSupplyCfgAddr: {supply.b, fxSupplyProgram},
		fxVaultCfgAddr:  {vault.b, fxVaultProgram},
		fxStrategyAddr:  {strategy.b, fxPricingProgram},
		fxRegistryAddr:  {registry.b, fxComplianceProgram},
		fxEscrowAddr:    {redemption.b, fxRedemptionProgram},
	}
}

func fxPrograms() BaselinePrograms {
	return BaselinePrograms{
		SupplyController: fxSupplyProgram, SupplyConfig: fxSupplyCfgAddr,
		Vault: fxVaultProgram, VaultConfig: fxVaultCfgAddr,
		Pricing: fxPricingProgram, Compliance: fxComplianceProgram, Redemption: fxRedemptionProgram,
	}
}

func TestReadBaselineFullDeployment(t *testing.T) {
	srv := fakeAccountServer(t, fullDeployment(t))
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err != nil {
		t.Fatalf("ReadBaseline: %v", err)
	}

	// auditor_eth was filled 0xA0, 0xA1, ... for 20 bytes.
	wantAuditor := "0xa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
	for _, tc := range []struct{ field, got, want string }{
		{"Auditor", b.Auditor, wantAuditor},
		{"Treasury", b.Treasury, fxTreasury},
		{"Treasurer", b.Treasurer, fxTreasurer},
		{"Pricer", b.Pricer, fxPricer},
		{"ComplianceOperator", b.ComplianceOperator, fxComplianceAuth},
		{"Pauser", b.Pauser, fxPauser},
		{"RedemptionManager", b.RedemptionManager, fxRedManager},
		{"PurchasePricePerWholeToken", b.PurchasePricePerWholeToken, "2000000"},
		{"RedemptionPricePerWholeToken", b.RedemptionPricePerWholeToken, "1950000"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if !b.Paused {
		t.Error("Paused = false, want true")
	}
	if !b.Finalized {
		t.Error("Finalized = false, want true")
	}
}

// TestReadBaselineNotBootstrapped: before `initialize` has run there are no
// accounts at all. This is the state the sanctioned pre-bootstrap boot spends
// its whole life in, so it must be an empty baseline and a NIL error — not a
// stream of failures on every 5s tick.
func TestReadBaselineNotBootstrapped(t *testing.T) {
	srv := fakeAccountServer(t, map[string]acct{})
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err != nil {
		t.Fatalf("ReadBaseline on a bare cluster: %v, want nil (absent accounts are not failures)", err)
	}
	if b != (Baseline{}) {
		t.Errorf("baseline = %+v, want zero", b)
	}
}

// TestReadBaselinePartial: the supply-controller and vault are initialized but
// set_system_addresses has not pinned the escrow yet, so the registry's escrow
// field is the zero pubkey — which is ALSO the System Program's address. A
// naive read would fetch that real account and report an owner mismatch; this
// must instead be treated as "not wired yet", leaving RedemptionManager unset
// while every other field still decodes.
func TestReadBaselinePartial(t *testing.T) {
	accounts := fullDeployment(t)
	registry := newAcct("Registry").
		pubkey(t, fxKey("registry.admin")).
		pubkey(t, fxKey("registry.pending_admin")).
		pubkey(t, fxComplianceAuth).
		pubkey(t, fxPauser).
		pubkey(t, fxVaultCfgAddr).
		zeroPubkey(). // escrow NOT pinned yet
		pubkey(t, fxSupplyCfgAddr).
		pubkey(t, fxKey("registry.rwa_mint")).
		boolean(false).boolean(false).boolean(false).u8(252)
	accounts[fxRegistryAddr] = acct{registry.b, fxComplianceProgram}
	srv := fakeAccountServer(t, accounts)
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err != nil {
		t.Fatalf("ReadBaseline: %v, want nil (an unpinned escrow is not a failure)", err)
	}
	if b.RedemptionManager != "" {
		t.Errorf("RedemptionManager = %q, want empty (escrow not pinned)", b.RedemptionManager)
	}
	if b.Treasury != fxTreasury || b.Pricer != fxPricer || b.ComplianceOperator != fxComplianceAuth {
		t.Errorf("the readable accounts must still decode: %+v", b)
	}
}

// TestReadBaselineRejectsWrongOwner: an account at the right address, of the
// right size and discriminator, but owned by another program must contribute
// NOTHING. Without the owner check any program could park a look-alike account
// and have its chosen pubkeys shown as this deployment's treasury/pauser.
func TestReadBaselineRejectsWrongOwner(t *testing.T) {
	accounts := fullDeployment(t)
	v := accounts[fxVaultCfgAddr]
	accounts[fxVaultCfgAddr] = acct{v.data, "SomeOtherProgram11111111111111111111111111"}
	srv := fakeAccountServer(t, accounts)
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatalf("err = %v, want an owner-mismatch error", err)
	}
	if b.Treasury != "" || b.Treasurer != "" {
		t.Errorf("a wrong-owner account must contribute nothing, got %+v", b)
	}
	// The vault Config is also where the strategy/registry addresses come
	// from, so rejecting it necessarily drops everything downstream too.
	if b.Pricer != "" || b.ComplianceOperator != "" {
		t.Errorf("downstream accounts must not be read via a rejected vault Config: %+v", b)
	}
	// ...but the supply-controller Config is read independently and stands.
	if b.Auditor == "" {
		t.Error("the independently-addressed supply Config should still decode")
	}
}

// TestReadBaselineRejectsBadDiscriminator guards the check the owner test
// cannot make: a different account TYPE declared by the same program.
func TestReadBaselineRejectsBadDiscriminator(t *testing.T) {
	accounts := fullDeployment(t)
	bad := append([]byte{}, accounts[fxStrategyAddr].data...)
	copy(bad[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	accounts[fxStrategyAddr] = acct{bad, fxPricingProgram}
	srv := fakeAccountServer(t, accounts)
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err == nil || !strings.Contains(err.Error(), "discriminator") {
		t.Fatalf("err = %v, want a discriminator error", err)
	}
	if b.Pricer != "" || b.PurchasePricePerWholeToken != "" {
		t.Errorf("a wrong-type account must contribute nothing, got %+v", b)
	}
}

// TestReadBaselineRejectsTruncated: a short account must error rather than
// decode a prefix — borshReader.take is what enforces this, and readFields
// propagates it.
func TestReadBaselineRejectsTruncated(t *testing.T) {
	accounts := fullDeployment(t)
	full := accounts[fxVaultCfgAddr]
	accounts[fxVaultCfgAddr] = acct{full.data[:40], full.owner} // discriminator + one pubkey
	srv := fakeAccountServer(t, accounts)
	defer srv.Close()

	b, err := ReadBaseline(context.Background(), NewRPCClient(srv.URL), fxPrograms(), "finalized")
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("err = %v, want a truncation error", err)
	}
	if b.Treasury != "" {
		t.Errorf("Treasury = %q, want empty from a truncated account", b.Treasury)
	}
}
