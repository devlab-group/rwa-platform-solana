import { useEffect, useMemo, useState, type ChangeEvent } from "react";
import type { Hex } from "../../lib/chain";
import { AsyncSection } from "../../components/AsyncSection";
import { PaginationFooter } from "../../components/PaginationFooter";
import { useAsync } from "../../hooks/useAsync";
import { usePaginatedList } from "../../hooks/usePaginatedList";
import { api, ApiError } from "../../lib/client";
import type { components } from "../../lib/api-types";
import { useWalletContext } from "../../context/walletContextValue";
import {
  formatIsoTimestamp,
  formatTokenAmount,
  toMinimalUnits,
} from "../../lib/format";
import { buildMetadataSkeleton } from "../../lib/jsonSchemaSkeleton";
import { buildSignerPolicy, type SignerPolicy } from "../../lib/signerPolicy";
import {
  connectWallet,
  sendMint,
  waitForTxReceipt,
  type MintAttestationInput,
} from "../../lib/wallet";

type AssetRecord = components["schemas"]["AssetRecord"];
type Project = components["schemas"]["Project"];
type StoredProfile = components["schemas"]["StoredProfile"];
type BootstrapConfig = components["schemas"]["BootstrapConfig"];

/** Empty-object fallback for the Metadata editor when no profile/schema is available. */
const EMPTY_METADATA = "{\n  \n}";

const RECORD_TONE: Record<NonNullable<AssetRecord["status"]>, string> = {
  Draft: "badge--neutral",
  Pending: "badge--info",
  Signed: "badge--info",
  Minted: "badge--success",
  Rejected: "badge--danger",
};

/**
 * Assets: metadata form + proofs, validation, IPFS status, audit package
 * download, auditor signature upload, and the resulting mint/burn relay.
 *
 * As on Setup, the metadata (`asset`) and `proofs` payloads are schema-driven
 * per project but untyped in the OpenAPI contract, so they're edited as JSON
 * here rather than via a generated form.
 */
export function Assets() {
  const records = usePaginatedList<AssetRecord>(
    (cursor, signal) => api.listRecords({ signal, cursor }),
    [],
  );
  // A record's `amount` is an RWA token amount; Project.decimals scales it
  // between the whole units the operator reads/enters and the minimal units the
  // record is stored and auditor-signed in.
  const project = useAsync<Project>((signal) => api.getProject({ signal }), []);
  // The signer policy's domain inputs (cluster genesis, and the supply/vault
  // Config PDAs) are NOT in Project.addresses — that carries program ids, which
  // are the wrong values for two of the four domain slots. They come from the
  // server's own contract.* config via GET /api/v1/config.
  const bootstrap = useAsync<BootstrapConfig>(
    (signal) => api.getConfig({ signal }),
    [],
  );
  const rwaDecimals =
    project.status === "success" ? project.data.decimals : undefined;

  // The record metadata is validated against the project's Asset Profile
  // `assetSchema`, so load the profile and pre-fill the Metadata editor with a
  // skeleton built from that schema (404 → none yet → empty template fallback).
  const profile = useAsync<StoredProfile | null>(
    (signal) => loadProfile(signal),
    [],
  );
  const metadataSkeleton = useMemo(() => {
    if (profile.status !== "success" || !profile.data) return undefined;
    const raw = profile.data.profile as Record<string, unknown> | undefined;
    return buildMetadataSkeleton(raw?.assetSchema);
  }, [profile.status, profile.data]);
  const recordIdLabel =
    (profile.status === "success" &&
      profile.data &&
      (profile.data.profile as Record<string, unknown>)?.recordIdLabel) ||
    undefined;

  // The signer policy pins the offline signer to this project's UUID — the same
  // UUID string generated at Setup and stored in the profile's raw doc, NOT the
  // bytes32 profileDigest/keccak. The signer compares it against profile.json
  // inside the .rwa package.
  const projectUuid =
    profile.status === "success" &&
    profile.data &&
    typeof (profile.data.profile as Record<string, unknown>)?.projectId ===
      "string"
      ? ((profile.data.profile as Record<string, unknown>).projectId as string)
      : undefined;

  // The auditor identity comes from the supply-controller's on-chain config
  // account. Until the server can read it, every .rwa package this page could
  // produce would carry a ZERO auditor: unsignable by the offline signer and
  // unmintable on-chain, but indistinguishable from a good package until the
  // auditor rejects it — after the whole offline round-trip.
  //
  // The server now refuses to build one (409), so this is not the safety
  // boundary; it exists so the admin is told BEFORE filling in a record form
  // that the deployment is not ready, instead of after.
  // Deliberately NOT "auditor is present": that would also hide these sections
  // while the project is still loading or 404s (pre-deploy), where they have
  // their own, more specific empty states and the banner below does not render
  // — leaving a blank page with no explanation. Gate only on the one case the
  // banner actually covers: the project loaded, and it has no auditor.
  const deploymentNotReady =
    project.status === "success" && !project.data.auditor;

  return (
    <div>
      <header className="app-main__header">
        <h1>Assets</h1>
        <p>
          Metadata records, IPFS packages, auditor signatures, and mint/burn
          relay.
        </p>
      </header>

      {deploymentNotReady && (
        <section className="card">
          <h2>Deployment not ready</h2>
          <p className="field__hint" role="status">
            The auditor address has not been read from the chain yet, so no
            asset package can be built: one produced now would carry a zero
            auditor and could be neither signed nor minted.
          </p>
          <p className="field__hint">
            This is normal immediately after bootstrapping — the server picks
            the auditor up from the supply-controller&apos;s config account
            within a few seconds. If it persists, the deployment is not
            bootstrapped or the server cannot reach its RPC endpoint (see{" "}
            <code className="mono">opsctl indexer probe</code>).
          </p>
        </section>
      )}

      {!deploymentNotReady && (
        <section className="card">
          <h2>Create record</h2>
          <CreateRecordForm
            onCreated={records.reload}
            rwaDecimals={rwaDecimals}
            metadataSkeleton={metadataSkeleton}
            recordIdLabel={
              typeof recordIdLabel === "string" ? recordIdLabel : undefined
            }
          />
        </section>
      )}

      {!deploymentNotReady && (
        <section className="card">
          <h2>Signer policy (offline signing trust root)</h2>
          <p className="field__hint">
            This is the <code className="mono">--policy policy.json</code> file
            the auditor needs for <code className="mono">signer sign</code>. It
            pins the attestation domain (cluster, supply-controller program and
            config PDA), the vault config PDA, the auditor, and the project they
            may sign for — the signer refuses anything that disagrees, and
            rejects the file outright if it carries any key not listed below.
            Download it and hand it to the auditor alongside the .rwa package.
          </p>
          <SignerPolicySection
            project={project.status === "success" ? project.data : undefined}
            projectUuid={projectUuid}
            bootstrap={
              bootstrap.status === "success" ? bootstrap.data : undefined
            }
          />
        </section>
      )}

      <section className="card">
        <h2>Records</h2>
        <AsyncSection
          state={records}
          onRetry={records.reload}
          empty={(d) => d.length === 0}
          emptyLabel="No asset records yet."
        >
          {(data) => (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Record ID</th>
                      <th>Status</th>
                      <th>Amount</th>
                      <th>Metadata digest</th>
                      <th>IPFS CID</th>
                      <th>Created</th>
                      <th>Package</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.map((r) => (
                      <RecordRow
                        key={r.recordId}
                        record={r}
                        rwaDecimals={rwaDecimals}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
              <PaginationFooter
                loadedCount={data.length}
                totalCount={records.totalCount}
                hasMore={records.hasMore}
                loadingMore={records.loadingMore}
                loadMoreError={records.loadMoreError}
                onLoadMore={records.loadMore}
              />
            </>
          )}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Auditor signature upload &amp; mint</h2>
        <p className="field__hint">
          Uploading a valid auditor signature broadcasts SupplyController.mint
          from your connected wallet; the server observes the on-chain Minted
          event and advances the record.
        </p>
        <SignatureUploadForm
          project={project.status === "success" ? project.data : undefined}
          records={records.status === "success" ? records.data : []}
          onMinted={records.reload}
        />
      </section>
    </div>
  );
}

/** Triggers a client-side download of `policy` as policy.json (public config — no wallet needed). */
function downloadSignerPolicy(policy: SignerPolicy): void {
  const blob = new Blob([JSON.stringify(policy, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = url;
    link.download = "policy.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

function SignerPolicySection({
  project,
  projectUuid,
  bootstrap,
}: {
  project: Project | undefined;
  projectUuid: string | undefined;
  bootstrap: BootstrapConfig | undefined;
}) {
  const policy = buildSignerPolicy(project, projectUuid, bootstrap);

  if (!policy) {
    return (
      <p className="field__hint">
        Bootstrap the deployment and create the asset profile first — the signer
        policy needs the cluster genesis, the supply-controller program and its
        config PDA, the vault config PDA, the auditor, the profile digest, and
        the project ID.
      </p>
    );
  }

  // Labels name the POLICY key, not a friendly synonym: an auditor comparing
  // this screen against the JSON they received should be able to match them
  // one-for-one, and "config"/"vault" being PDAs rather than program ids is
  // exactly the distinction worth making visible.
  const rows: [string, string][] = [
    ["cluster (genesis hash)", policy.cluster],
    ["program (supply-controller)", policy.program],
    ["config (supply-controller PDA)", policy.config],
    ["vault (vault config PDA)", policy.vault],
    ["auditor", policy.auditor],
    ["projectId", policy.projectId],
    ["profileDigest", policy.profileDigest],
  ];

  return (
    <div>
      <dl className="tx-preview__grid">
        {rows.map(([label, value]) => (
          <div className="tx-preview__row" key={label}>
            <dt>{label}</dt>
            <dd className="mono">{value}</dd>
          </div>
        ))}
      </dl>
      <button
        type="button"
        className="button button--primary"
        onClick={() => downloadSignerPolicy(policy)}
      >
        Download policy.json
      </button>
    </div>
  );
}

/** Fetches the stored Asset Profile, mapping the admin-only 404 (none yet) to null. */
async function loadProfile(signal: AbortSignal): Promise<StoredProfile | null> {
  try {
    return await api.getProfile({ signal });
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

function RecordRow({
  record,
  rwaDecimals,
}: {
  record: AssetRecord;
  rwaDecimals: number | undefined;
}) {
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  // A plain `<a href>` can't attach the operator's bearer session, so the
  // protected package endpoint 403s. Fetch it authenticated instead and hand
  // the browser a Blob URL to download.
  async function handleDownload() {
    if (!record.recordId) return;
    setError(null);
    setDownloading(true);
    try {
      const blob = await api.downloadPackage(record.recordId);
      const url = URL.createObjectURL(blob);
      try {
        const link = document.createElement("a");
        link.href = url;
        link.download = `${record.recordId}.rwa`;
        document.body.appendChild(link);
        link.click();
        link.remove();
      } finally {
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Download failed.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <tr>
      <td className="mono">{record.recordId}</td>
      <td>
        {record.status && (
          <span className={`badge ${RECORD_TONE[record.status]}`}>
            {record.status}
          </span>
        )}
      </td>
      <td>{formatTokenAmount(record.amount ?? "", rwaDecimals)}</td>
      <td className="mono">{record.metadataDigest ?? "—"}</td>
      <td className="mono">{record.cid ?? "—"}</td>
      <td>{formatIsoTimestamp(record.createdAt)}</td>
      <td>
        {record.recordId && (
          <>
            <button
              type="button"
              className="button button--secondary"
              onClick={handleDownload}
              disabled={downloading}
            >
              {downloading ? "Downloading…" : "Download .rwa"}
            </button>
            {error && (
              <p className="async-state--error" role="alert">
                {error}
              </p>
            )}
          </>
        )}
      </td>
    </tr>
  );
}

const PROOFS_EXAMPLE = `[
  {
    "type": "custody-attestation",
    "sha256": "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
    "uri": "ipfs://bafybeih..."
  }
]`;

function CreateRecordForm({
  onCreated,
  rwaDecimals,
  metadataSkeleton,
  recordIdLabel,
}: {
  onCreated: () => void;
  rwaDecimals: number | undefined;
  /** Metadata placeholder derived from the profile's assetSchema (undefined while loading / no profile). */
  metadataSkeleton: string | undefined;
  /** The profile's recordIdLabel (e.g. "Serial number"), used to make the Record ID hint concrete. */
  recordIdLabel: string | undefined;
}) {
  const [recordId, setRecordId] = useState("");
  const [amount, setAmount] = useState("");
  const [assetJson, setAssetJson] = useState(
    metadataSkeleton ?? EMPTY_METADATA,
  );
  const [assetEdited, setAssetEdited] = useState(false);
  const [proofsJson, setProofsJson] = useState("[]");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // The profile (and thus the schema skeleton) loads after this form mounts.
  // Seed the Metadata editor once it arrives, but never clobber edits the
  // operator has already started making.
  useEffect(() => {
    if (metadataSkeleton && !assetEdited) setAssetJson(metadataSkeleton);
  }, [metadataSkeleton, assetEdited]);

  async function handleCreate() {
    setError(null);
    if (rwaDecimals === undefined) {
      setError("Token decimals not available yet — project still loading.");
      return;
    }
    let asset: unknown;
    let proofs: unknown;
    try {
      asset = JSON.parse(assetJson);
      proofs = JSON.parse(proofsJson);
    } catch {
      setError("Asset metadata and proofs must be valid JSON.");
      return;
    }
    // Human whole units -> the RWA token's minimal units, the form in which the
    // record is stored and auditor-signed.
    let minimalAmount: string;
    try {
      minimalAmount = toMinimalUnits(amount, rwaDecimals);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Invalid amount.");
      return;
    }
    setSubmitting(true);
    try {
      await api.createRecord(
        {
          recordId,
          asset: asset as Record<string, never>,
          amount: minimalAmount,
          proofs: proofs as Record<string, never>[],
        },
        `create-${recordId}`,
      );
      setRecordId("");
      setAmount("");
      onCreated();
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Failed to create record.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <div className="field">
        <label htmlFor="recordId">Record ID</label>
        <input
          id="recordId"
          value={recordId}
          onChange={(e) => setRecordId(e.target.value)}
          aria-describedby="recordId-hint"
        />
        <span className="field__hint" id="recordId-hint">
          A unique identifier for this asset record
          {recordIdLabel ? ` — the ${recordIdLabel.toLowerCase()}` : ""} (your
          own reference, e.g. a serial/deed/invoice number). Immutable once
          created.
        </span>
      </div>
      <div className="field">
        <label htmlFor="amount">Amount (whole units)</label>
        <input
          id="amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          aria-describedby="amount-hint"
        />
        <span className="field__hint" id="amount-hint">
          How many whole tokens this record represents (e.g. 100.5). Converted
          to the token&apos;s minimal units on submit using the project&apos;s
          decimals.
        </span>
      </div>
      <div className="field">
        <label htmlFor="assetJson">Metadata (asset fields as JSON)</label>
        <textarea
          id="assetJson"
          rows={8}
          className="mono"
          value={assetJson}
          onChange={(e) => {
            setAssetJson(e.target.value);
            setAssetEdited(true);
          }}
          aria-describedby="assetJson-hint"
        />
        <span className="field__hint" id="assetJson-hint">
          The asset&apos;s metadata, matching this project&apos;s Asset Profile
          schema. Pre-filled with the schema&apos;s fields — replace the
          placeholder values. Validated against the schema server-side.
        </span>
      </div>
      <div className="field">
        <label htmlFor="proofsJson">Proof hashes (JSON array)</label>
        <textarea
          id="proofsJson"
          rows={3}
          className="mono"
          value={proofsJson}
          onChange={(e) => setProofsJson(e.target.value)}
          aria-describedby="proofsJson-hint"
        />
        <span className="field__hint" id="proofsJson-hint">
          Optional references to off-chain evidence (custody attestations,
          appraisals, audit certificates). A JSON array of{" "}
          <code className="mono">{"{ type, sha256, uri? }"}</code> entries:{" "}
          <strong>type</strong> is your own label, <strong>sha256</strong> is
          the document&apos;s SHA-256 as 64 lowercase hex chars (no{" "}
          <code className="mono">0x</code>), <strong>uri</strong> (optional) is
          where it&apos;s hosted. Leave as <code className="mono">[]</code> if
          there are none. Example:
        </span>
        <pre className="field__example mono">{PROOFS_EXAMPLE}</pre>
      </div>
      <button
        type="button"
        className="button button--primary"
        onClick={handleCreate}
        disabled={submitting || !recordId || !amount}
      >
        {submitting ? "Creating…" : "Create record"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/** The string fields a signed-result.json carries (signer/internal/output/output.go's SignedResult). */
const SIGNED_RESULT_STRING_FIELDS = [
  "formatVersion",
  "chain",
  "auditor",
  "primaryType",
  "cluster",
  "program",
  "config",
  "attestationDigest",
  "signature",
  "signedAt",
] as const;

/**
 * Normalized view of the parsed signed-result document — the fields this form
 * needs. `signature` is a 65-byte hex string: the 64-byte compact [R||S]
 * secp256k1 signature with a 1-byte recovery id appended (see
 * parseSignedResult and lib/wallet.ts's sendMint, which splits it back
 * apart).
 */
export interface ParsedSignature {
  auditor: string;
  primaryType: string;
  signedAt: string;
  signature: Hex;
}

/**
 * Parses a signed-result.json (formatVersion "solana-1.0"; see
 * signer/internal/output/output.go), checking every required field is
 * present and a non-empty string. The server re-validates authoritatively
 * (signature verification, digest, enum, format) before observing the mint —
 * this only catches an obviously wrong file before the round trip. Packs the
 * 64-byte compact signature + separate numeric recoveryId into the single
 * 65-byte hex `signature` slot lib/wallet.ts's sendMint expects.
 */
// Exported for direct unit testing (Assets.test.tsx) — otherwise unused
// outside this module.
export function parseSignedResult(text: string): ParsedSignature {
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch {
    throw new Error("The selected file is not valid JSON.");
  }
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new Error("signed-result.json must be a JSON object.");
  }
  const rec = obj as Record<string, unknown>;
  const missing = SIGNED_RESULT_STRING_FIELDS.filter(
    (k) => typeof rec[k] !== "string" || rec[k] === "",
  );
  if (missing.length > 0) {
    throw new Error(
      `Not a signed-result.json — missing field(s): ${missing.join(", ")}.`,
    );
  }
  if (rec.formatVersion !== "solana-1.0" || rec.chain !== "solana") {
    throw new Error(
      'Not a signed-result.json — expected formatVersion "solana-1.0" and chain "solana".',
    );
  }
  const signature = String(rec.signature);
  if (!/^0x[0-9a-fA-F]{128}$/.test(signature)) {
    throw new Error(
      "Signature must be the 64-byte compact form (0x + 128 hex chars).",
    );
  }
  const recoveryId = rec.recoveryId;
  if (
    typeof recoveryId !== "number" ||
    (recoveryId !== 0 && recoveryId !== 1)
  ) {
    throw new Error("signed-result.json's recoveryId must be 0 or 1.");
  }
  return {
    auditor: String(rec.auditor),
    primaryType: String(rec.primaryType),
    signedAt: String(rec.signedAt),
    signature: `${signature}${recoveryId.toString(16).padStart(2, "0")}` as Hex,
  };
}

function SignatureUploadForm({
  project,
  records,
  onMinted,
}: {
  project: Project | undefined;
  records: AssetRecord[];
  onMinted: () => void;
}) {
  const wallet = useWalletContext();
  const [recordId, setRecordId] = useState("");
  // The whole signed-result document is read from the uploaded file rather
  // than hand-typed field by field — the auditor's signer produces it (see
  // parseSignedResult), so re-entering its contents by hand is error-prone
  // and pointless.
  const [signed, setSigned] = useState<ParsedSignature | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [txHash, setTxHash] = useState<string | null>(null);

  async function handleFile(e: ChangeEvent<HTMLInputElement>) {
    setError(null);
    setTxHash(null);
    setSigned(null);
    setFileName(null);
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setSigned(parseSignedResult(text));
      setFileName(file.name);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read the file.");
    }
  }

  async function handleMint() {
    if (!signed) return;
    setError(null);
    setTxHash(null);

    // The MintAttestation is assembled from the record (recordKey/nonce/
    // validUntil/metadataDigest/amount, now exposed on GET /assets/records) and
    // the project (auditor/profileDigest/supplyController). Both must be
    // loaded and the record must carry its attestation fields.
    if (!project) {
      setError("Project not loaded yet — try again in a moment.");
      return;
    }
    const record = records.find((r) => r.recordId === recordId);
    if (!record) {
      setError(
        "No loaded record matches that ID. Check the ID (it must match a record above; load more records if it's on a later page).",
      );
      return;
    }
    const supplyController = project.addresses?.supplyController;
    if (!supplyController) {
      setError(
        "Project is not fully deployed (missing SupplyController address).",
      );
      return;
    }
    if (
      record.recordKey === undefined ||
      record.nonce === undefined ||
      record.validUntil === undefined ||
      record.metadataDigest === undefined ||
      record.amount === undefined
    ) {
      setError(
        "This record is missing its attestation fields (recordKey/nonce/validUntil/metadata/amount).",
      );
      return;
    }
    if (!project.auditor || !project.profileDigest) {
      setError("Project is missing its auditor or profile digest.");
      return;
    }
    // The signed-result.json must be from the project's auditor — a mismatch
    // would revert on-chain (the SupplyController checks the recovered signer),
    // so surface it clearly before broadcasting.
    if (signed.auditor.toLowerCase() !== project.auditor.toLowerCase()) {
      setError(
        `Signed by ${signed.auditor}, but this project's auditor is ${project.auditor}. Wrong signed-result.json.`,
      );
      return;
    }

    const attestation: MintAttestationInput = {
      auditor: project.auditor,
      profileDigest: project.profileDigest as Hex,
      recordKey: record.recordKey as Hex,
      metadataDigest: record.metadataDigest as Hex,
      amount: BigInt(record.amount),
      nonce: BigInt(record.nonce),
      validUntil: BigInt(record.validUntil),
    };

    // The mint is broadcast from the connected wallet; the admin is normally
    // already connected from login, connect on demand if not.
    let from = wallet.address;
    if (!from) {
      try {
        from = (await connectWallet()).address;
      } catch {
        setError("Connect your wallet to mint.");
        return;
      }
    }

    setSubmitting(true);
    try {
      const hash = await sendMint(
        from,
        supplyController,
        attestation,
        signed.signature,
      );
      await waitForTxReceipt(hash);
      setTxHash(hash);
      // The server's ReconcileMinted flips the record to Minted once it observes
      // the on-chain Minted event; reload so the row reflects it.
      onMinted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Mint transaction failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <div className="field">
        <label htmlFor="sigRecordId">Record ID</label>
        <input
          id="sigRecordId"
          value={recordId}
          onChange={(e) => setRecordId(e.target.value)}
          aria-describedby="sigRecordId-hint"
        />
        <span className="field__hint" id="sigRecordId-hint">
          The record this attestation mints — must match a record above (the ID
          the .rwa package was built for). Its recordKey, nonce, validUntil,
          metadata digest, and amount are read from that record.
        </span>
      </div>
      <div className="field">
        <label htmlFor="signedResultFile">Signed result</label>
        <input
          id="signedResultFile"
          type="file"
          accept="application/json,.json"
          onChange={handleFile}
          aria-describedby="signedResultFile-hint"
        />
        <span className="field__hint" id="signedResultFile-hint">
          Upload the <code className="mono">signed-result.json</code> the
          auditor produced from the .rwa package. Its signature is bound into
          the on-chain MintAttestation and verified on-chain; its auditor
          address is cross-checked against the project&apos;s auditor before
          broadcasting.
        </span>
      </div>

      {signed && (
        <dl className="tx-preview__grid" role="status">
          <div className="tx-preview__row">
            <dt>File</dt>
            <dd>{fileName}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Auditor</dt>
            <dd className="mono">{signed.auditor}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Attestation</dt>
            <dd>{signed.primaryType}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Signed at</dt>
            <dd>{signed.signedAt}</dd>
          </div>
        </dl>
      )}

      <button
        type="button"
        className="button button--primary"
        onClick={handleMint}
        disabled={submitting || !recordId || !signed}
      >
        {submitting ? "Minting…" : "Upload signature & mint"}
      </button>
      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}
      {txHash && (
        <p role="status">
          Mint broadcast. Transaction: <span className="mono">{txHash}</span>.
          The record flips to Minted once the server observes it.
        </p>
      )}
    </div>
  );
}
