#!/usr/bin/env bash
# deploy.sh — deploy (or upgrade) all six RWA programs in one pass.
#
# Wraps the per-program `solana program deploy` invocation from
# solana/README.md step 4 in a loop, so you don't hand-substitute six binary
# names, six keypair paths, and the same five flags every time. Same command,
# same semantics — localnet, devnet, testnet or mainnet-beta:
#
#   scripts/deploy.sh --url http://127.0.0.1:8899 \
#     --keypair ../docker/solana/test-wallet-keypair.json
#
#   scripts/deploy.sh --url "$HELIUS_URL" --keypair ~/deployer.json \
#     --with-compute-unit-price 50000
#
# Every program is deployed upgradeable with the deployer as upgrade authority
# (go-live needs it — README step 8), and the script preflights everything it
# can before spending anything: binaries and keypairs present, program ids
# matching Anchor.toml, cluster reachable, payer funded. A mainnet-beta genesis
# hash requires an explicit confirmation.
#
# Deploys are resumable by default: each program writes through a fixed buffer
# keypair (`target/deploy/<program>-upgrade-buffer.json`), so a large deploy
# that dies partway is retried and continues into the same buffer instead of
# abandoning a rent-funded account on-chain. Re-running the script after a
# failure resumes the same way.
#
# This script only puts bytecode on-chain. Wiring the deployment (mint, PDAs,
# `initialize`, `set_system_addresses`, `finalize`) is `scripts/bootstrap.mjs`.

set -euo pipefail

# Program order follows the README runbook: dependencies of the go-live CPI
# chain first. Deploy order does not matter to the runtime — nothing is
# initialized here — but a consistent order keeps logs comparable across runs.
PROGRAMS_ALL=(
  rwa_compliance
  rwa_transfer_hook
  rwa_supply_controller
  rwa_pricing
  rwa_vault
  rwa_redemption
)

INVOCATION_PWD="$PWD"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOLANA_DIR="$(dirname -- "$SCRIPT_DIR")"

MAINNET_GENESIS="5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"

URL=""
KEYPAIR=""
UPGRADE_AUTHORITY=""
PROGRAM_DIR="target/deploy"
CU_PRICE=""
SELECTED=""
ATTEMPTS=3
USE_RPC=1
RESUME=1
ID_CHECK=1
DRY_RUN=0
ASSUME_YES=0

usage() {
  cat <<'EOF'
Usage: scripts/deploy.sh --url <RPC_URL> --keypair <PATH> [options]

Required:
  -u, --url <URL>                 RPC endpoint or moniker (localhost, devnet,
                                  testnet, mainnet-beta). Use a paid/dedicated
                                  RPC on public clusters — the public endpoint
                                  rejects large program deploys.
  -k, --keypair <PATH>            Deployer keypair: fee payer and default
                                  signer, and the upgrade authority unless
                                  --upgrade-authority overrides it.

Options:
  -a, --upgrade-authority <PATH>  Upgrade-authority keypair (default: --keypair).
  -p, --programs <LIST>           Comma-separated subset to deploy, e.g.
                                  rwa_vault,rwa_redemption (default: all six).
  -d, --program-dir <DIR>         Directory holding <program>.so and
                                  <program>-keypair.json (default: target/deploy).
      --with-compute-unit-price <MICROLAMPORTS>
                                  Priority fee; helps large deploys land.
      --attempts <N>              Attempts per program (default: 3). Retries
                                  resume into the same buffer.
      --no-resume                 Let the CLI pick an ephemeral buffer instead
                                  of a fixed <program>-upgrade-buffer.json.
      --no-use-rpc                Drop --use-rpc (it is passed by default;
                                  custom validator ports break the TPU client).
      --skip-id-check             Do not compare deploy keypairs against the
                                  program ids in Anchor.toml.
  -n, --dry-run                   Print the deploy commands and exit.
  -y, --yes                       Skip the mainnet-beta confirmation prompt.
  -h, --help                      This text.

Exit status is non-zero if any program failed to deploy; the summary names it.
EOF
}

log()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    \033[32m✅ %s\033[0m\n' "$*"; }
warn() { printf '    \033[33m⚠️  %s\033[0m\n' "$*" >&2; }
die()  { printf '\n\033[31m❌ %s\033[0m\n' "$*" >&2; exit 1; }

# Resolve a user-supplied path against the directory the user ran the script
# from, before we cd into solana/ — so relative paths mean what they look like.
abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    ~*) printf '%s\n' "${1/#\~/$HOME}" ;;
    *)  printf '%s\n' "$INVOCATION_PWD/$1" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url)                     URL="${2:?--url needs a value}"; shift 2 ;;
    -k|--keypair)                 KEYPAIR="${2:?--keypair needs a value}"; shift 2 ;;
    -a|--upgrade-authority)       UPGRADE_AUTHORITY="${2:?--upgrade-authority needs a value}"; shift 2 ;;
    -p|--programs)                SELECTED="${2:?--programs needs a value}"; shift 2 ;;
    -d|--program-dir)             PROGRAM_DIR="${2:?--program-dir needs a value}"; shift 2 ;;
    --with-compute-unit-price)    CU_PRICE="${2:?--with-compute-unit-price needs a value}"; shift 2 ;;
    --attempts)                   ATTEMPTS="${2:?--attempts needs a value}"; shift 2 ;;
    --no-resume)                  RESUME=0; shift ;;
    --no-use-rpc)                 USE_RPC=0; shift ;;
    --skip-id-check)              ID_CHECK=0; shift ;;
    -n|--dry-run)                 DRY_RUN=1; shift ;;
    -y|--yes)                     ASSUME_YES=1; shift ;;
    -h|--help)                    usage; exit 0 ;;
    *)                            usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ -n "$URL" ]]     || { usage >&2; die "--url is required"; }
[[ -n "$KEYPAIR" ]] || { usage >&2; die "--keypair is required"; }
[[ "$ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || die "--attempts must be a positive integer"

KEYPAIR="$(abs_path "$KEYPAIR")"
UPGRADE_AUTHORITY="${UPGRADE_AUTHORITY:-$KEYPAIR}"
[[ "$UPGRADE_AUTHORITY" == "$KEYPAIR" ]] || UPGRADE_AUTHORITY="$(abs_path "$UPGRADE_AUTHORITY")"
PROGRAM_DIR="$(abs_path "$PROGRAM_DIR")"

cd "$SOLANA_DIR"

# Which programs.
programs=()
if [[ -z "$SELECTED" ]]; then
  programs=("${PROGRAMS_ALL[@]}")
else
  IFS=',' read -r -a requested <<<"$SELECTED"
  for want in "${requested[@]}"; do
    want="${want// /}"
    [[ -n "$want" ]] || continue
    want="${want//-/_}"          # accept rwa-vault as well as rwa_vault
    found=0
    for known in "${PROGRAMS_ALL[@]}"; do
      [[ "$want" == "$known" ]] && { programs+=("$known"); found=1; break; }
    done
    (( found )) || die "unknown program '$want' (known: ${PROGRAMS_ALL[*]})"
  done
  [[ ${#programs[@]} -gt 0 ]] || die "--programs matched nothing"
fi

# ---------------------------------------------------------------- preflight ---

log "Preflight"

command -v solana >/dev/null        || die "the 'solana' CLI is not on PATH"
command -v solana-keygen >/dev/null || die "'solana-keygen' is not on PATH"
info "solana CLI: $(solana --version)"

[[ -d "$PROGRAM_DIR" ]] || die "program dir not found: $PROGRAM_DIR (run 'anchor build' first)"
[[ -f "$KEYPAIR" ]]     || die "deployer keypair not found: $KEYPAIR"
[[ -f "$UPGRADE_AUTHORITY" ]] || die "upgrade-authority keypair not found: $UPGRADE_AUTHORITY"

PAYER_PUBKEY="$(solana-keygen pubkey "$KEYPAIR")" || die "cannot read a pubkey from $KEYPAIR"
AUTHORITY_PUBKEY="$(solana-keygen pubkey "$UPGRADE_AUTHORITY")" \
  || die "cannot read a pubkey from $UPGRADE_AUTHORITY"

# Collect and validate every program's inputs before spending anything: a
# partial deploy that stops on a missing file in the middle is the failure mode
# this loop exists to avoid.
declare -a SO_PATH=() KP_PATH=() PROGRAM_ID=() SO_SIZE=()
id_mismatch=0
total_bytes=0

for name in "${programs[@]}"; do
  so="$PROGRAM_DIR/$name.so"
  kp="$PROGRAM_DIR/$name-keypair.json"
  [[ -f "$so" ]] || die "missing binary: $so (run 'anchor build')"
  [[ -f "$kp" ]] || die "missing program keypair: $kp (see solana/README.md step 1)"

  pid="$(solana-keygen pubkey "$kp")" || die "cannot read a pubkey from $kp"
  size="$(wc -c <"$so" | tr -d ' ')"

  if (( ID_CHECK )); then
    # Anchor.toml is the source of truth the Rust declare_id!s are synced to;
    # a deploy keypair that disagrees with it means the bytecode's own id is not
    # the address it is landing on, and every PDA/CPI check will fail on-chain.
    declared="$(sed -nE "s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" Anchor.toml | head -1)"
    if [[ -z "$declared" ]]; then
      warn "$name: no program id in Anchor.toml — cannot cross-check"
    elif [[ "$declared" != "$pid" ]]; then
      warn "$name: Anchor.toml says $declared but $name-keypair.json is $pid"
      id_mismatch=1
    fi
  fi

  SO_PATH+=("$so"); KP_PATH+=("$kp"); PROGRAM_ID+=("$pid"); SO_SIZE+=("$size")
  total_bytes=$((total_bytes + size))
done

if (( id_mismatch )); then
  die "program id mismatch (above). Run 'anchor keys sync && anchor build', or pass --skip-id-check if this is deliberate."
fi

printf '\n    %-24s %10s  %s\n' "PROGRAM" "BYTES" "PROGRAM ID"
for i in "${!programs[@]}"; do
  printf '    %-24s %10s  %s\n' "${programs[$i]}" "${SO_SIZE[$i]}" "${PROGRAM_ID[$i]}"
done
printf '\n'
ok "${#programs[@]} program binaries and keypairs present (${total_bytes} bytes total)"

# Cluster identity. Doubles as a reachability check on the RPC endpoint.
GENESIS="$(solana genesis-hash --url "$URL" 2>/dev/null || true)"
[[ -n "$GENESIS" ]] || die "cannot reach the cluster at $URL"
info "cluster genesis: $GENESIS"
if [[ "$GENESIS" == "$MAINNET_GENESIS" ]]; then
  IS_MAINNET=1
  warn "this is MAINNET-BETA"
else
  IS_MAINNET=0
fi

info "fee payer:        $PAYER_PUBKEY"
info "upgrade authority: $AUTHORITY_PUBKEY"
if [[ "$AUTHORITY_PUBKEY" != "$PAYER_PUBKEY" ]]; then
  warn "upgrade authority is not the fee payer — both keypairs sign each deploy"
fi

BALANCE="$(solana balance "$PAYER_PUBKEY" --url "$URL" 2>/dev/null || true)"
if [[ -n "$BALANCE" ]]; then
  info "fee-payer balance: $BALANCE"
else
  warn "could not read the fee-payer balance"
fi

# Rent for a fresh upgradeable program account is charged on 2× the binary
# size; upgrades of already-deployed programs cost only fees. Informational —
# the CLI reports the exact shortfall if the payer is short.
if rent="$(solana rent $((2 * total_bytes)) --url "$URL" 2>/dev/null | sed -nE 's/^Rent-exempt minimum: (.*)$/\1/p')"; then
  [[ -n "$rent" ]] && info "first-time deploy of all selected programs needs about $rent (upgrades: fees only)"
fi

if (( IS_MAINNET )) && (( ! ASSUME_YES )) && (( ! DRY_RUN )); then
  [[ -t 0 ]] || die "mainnet-beta deploy with no tty: pass --yes to confirm non-interactively"
  printf '\n    Deploy %d program(s) to MAINNET-BETA as %s? Type "deploy" to continue: ' \
    "${#programs[@]}" "$PAYER_PUBKEY"
  read -r confirmation
  [[ "$confirmation" == "deploy" ]] || die "aborted"
fi

# ------------------------------------------------------------------ deploy ---

deploy_cmd() {  # $1 = index; echoes the argv, one element per line
  local i="$1"
  printf '%s\n' solana program deploy "${SO_PATH[$i]}" \
    --program-id "${KP_PATH[$i]}" \
    --url "$URL" \
    --keypair "$KEYPAIR" \
    --upgrade-authority "$UPGRADE_AUTHORITY"
  (( USE_RPC )) && printf '%s\n' --use-rpc
  [[ -n "$CU_PRICE" ]] && printf '%s\n' --with-compute-unit-price "$CU_PRICE"
  if (( RESUME )); then
    printf '%s\n' --buffer "$PROGRAM_DIR/${programs[$i]}-upgrade-buffer.json"
  fi
  return 0
}

if (( DRY_RUN )); then
  log "Dry run — commands that would be executed"
  for i in "${!programs[@]}"; do
    printf '\n    # %s\n    ' "${programs[$i]}"
    mapfile -t argv < <(deploy_cmd "$i")
    printf '%q ' "${argv[@]}"
    printf '\n'
  done
  printf '\n'
  exit 0
fi

declare -a STATUS=()
failures=0

for i in "${!programs[@]}"; do
  name="${programs[$i]}"
  log "[$((i + 1))/${#programs[@]}] $name → ${PROGRAM_ID[$i]}"

  if (( RESUME )); then
    buffer_kp="$PROGRAM_DIR/$name-upgrade-buffer.json"
    if [[ ! -f "$buffer_kp" ]]; then
      # A fixed buffer address per program is what makes a retry a resume: the
      # CLI writes into the existing partially-filled buffer instead of funding
      # a new one and orphaning the old.
      solana-keygen new --no-bip39-passphrase --silent -o "$buffer_kp" >/dev/null \
        || die "cannot create buffer keypair $buffer_kp"
      info "created buffer keypair $name-upgrade-buffer.json"
    fi
  fi

  mapfile -t argv < <(deploy_cmd "$i")

  attempt=1
  deployed=0
  while (( attempt <= ATTEMPTS )); do
    (( attempt > 1 )) && info "retry $attempt/$ATTEMPTS (resuming the same buffer)"
    if "${argv[@]}"; then
      deployed=1
      break
    fi
    attempt=$((attempt + 1))
  done

  if (( deployed )); then
    ok "$name deployed"
    STATUS+=("ok")
    # Read the account back: confirms the deploy landed and that the upgrade
    # authority is the key we intended, which go-live depends on.
    solana program show "${PROGRAM_ID[$i]}" --url "$URL" 2>/dev/null \
      | sed -nE 's/^(Authority|Last Deployed In Slot|Data Length):(.*)$/    \1:\2/p' || true
  else
    warn "$name FAILED after $ATTEMPTS attempt(s)"
    if (( RESUME )); then
      warn "buffer kept at $PROGRAM_DIR/$name-upgrade-buffer.json — re-run to resume, or 'solana program close --buffers' to reclaim its rent"
    else
      warn "check the CLI output above for a recovery buffer pubkey: solana program deploy --buffer <PUBKEY> …"
    fi
    STATUS+=("FAILED")
    failures=$((failures + 1))
  fi
done

# ----------------------------------------------------------------- summary ---

log "Summary"
printf '    %-24s %-8s %s\n' "PROGRAM" "STATUS" "PROGRAM ID"
for i in "${!programs[@]}"; do
  printf '    %-24s %-8s %s\n' "${programs[$i]}" "${STATUS[$i]}" "${PROGRAM_ID[$i]}"
done
printf '\n'

if (( failures )); then
  die "$failures of ${#programs[@]} program(s) failed — re-run the script to resume the unfinished ones"
fi

ok "all ${#programs[@]} program(s) on-chain at $URL"
info "record the ids and 'sha256sum $PROGRAM_DIR/*.so' in deployment-manifest.json"
info "next: node scripts/bootstrap.mjs --config scripts/bootstrap.config.json"
