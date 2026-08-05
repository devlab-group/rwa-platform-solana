import { useEffect, useRef, useState } from "react";
import { AsyncSection } from "../../components/AsyncSection";
import { useAsync } from "../../hooks/useAsync";
import { api, ApiError } from "../../lib/client";
import type { components } from "../../lib/api-types";

type Project = components["schemas"]["Project"];
type ValidationResult = components["schemas"]["ValidationResult"];
type StoredProfile = components["schemas"]["StoredProfile"];

/**
 * The deployment lifecycle as the UI cares about it. "unknown" is the initial
 * pre-first-load value; "not-deployed" folds together a 404 (no project yet)
 * and the server's explicit "Undeployed". The rest mirror Project.status.
 */
type DeployStatus =
  "unknown" | "not-deployed" | "Deploying" | "Verifying" | "Active" | "Failed";

/** How often to re-poll GET /project while a deployment is in a non-terminal state. */
const DEPLOY_POLL_MS = 3000;

/**
 * Setup: Asset Profile editor + validation preview, chain/role config,
 * prices, redemption timeout, deployment, verification.
 *
 * The Asset Profile schema itself is per-project and is not part of the
 * frozen OpenAPI contract (CreateRecordRequest.asset is an untyped object),
 * so the editor below is a JSON editor validated server-side via
 * POST /api/v1/profile/validate rather than a generated form.
 *
 * Setup is an explicit two-step sequence — validate (pure) then create/persist
 * (POST /api/v1/profile, admin-only, create-once).
 *
 * The profile is authored OFFLINE and pasted here, not composed here first: the
 * supply-controller commits to profileDigest at `initialize` and exposes no
 * setter, so the profile is fixed before the bootstrap — which is before this
 * server (and therefore this screen) can run at all. See
 * docs/operator/operator-guide.md §3. The server rejects any document that
 * doesn't hash to the digest it read off the on-chain config account, so the
 * digest shown after creation is a confirmation, never an input to deployment.
 */
export function Setup() {
  const project = useAsync<Project>((signal) => api.getProject({ signal }), []);
  // The profile is create-once and persisted server-side, so load it on mount
  // (GET /api/v1/profile, 404 → none yet). Repopulating from it means a reload
  // or navigation lands back on the already-persisted profile with Deployment
  // unlocked, instead of the empty create form that would force re-creation
  // (the server 409s on a second create anyway).
  const storedProfile = useAsync<StoredProfile | null>(
    (signal) => loadStoredProfile(signal),
    [],
  );
  // A profile persisted this session (fresh create) overrides the loaded one;
  // otherwise the loaded profile (if any) is the created/persisted state.
  const [createdProfile, setCreatedProfile] = useState<CreatedProfile | null>(
    null,
  );
  const loadedProfile =
    storedProfile.status === "success" && storedProfile.data
      ? storedToCreatedProfile(storedProfile.data)
      : null;
  const profile = createdProfile ?? loadedProfile;

  // Sticky deploy status derived from GET /project. Kept in state (updated only
  // on a resolved load) rather than read straight off `project` so it survives
  // the brief loading flip each poll's reload causes — otherwise the gate would
  // flicker and the polling effect below would tear itself down mid-cycle.
  const [deployStatus, setDeployStatus] = useState<DeployStatus>("unknown");
  const [deployNote, setDeployNote] = useState<string>("");
  useEffect(() => {
    if (project.status === "success") {
      const s = project.data.status;
      setDeployStatus(!s || s === "Undeployed" ? "not-deployed" : s);
      setDeployNote(project.data.verificationNote ?? "");
    } else if (project.status === "error") {
      // GET /project 404s before the first deploy — treat as not-yet-deployed.
      setDeployStatus("not-deployed");
      setDeployNote("");
    }
    // On "loading" (a poll's in-flight reload) keep the last known status.
  }, [project.status, project.data]);

  // Poll GET /project while the deployment is mid-flight so the admin always
  // sees current status, stopping at a terminal state (Active/Failed) and on
  // unmount. reload's identity changes each render, so read it through a ref to
  // keep the interval keyed only on the (sticky) status.
  const reloadRef = useRef(project.reload);
  reloadRef.current = project.reload;
  useEffect(() => {
    if (deployStatus !== "Deploying" && deployStatus !== "Verifying") return;
    const id = setInterval(() => reloadRef.current(), DEPLOY_POLL_MS);
    return () => clearInterval(id);
  }, [deployStatus]);

  return (
    <div>
      <header className="app-main__header">
        <h1>Setup</h1>
        <p>
          Chain and role configuration, pricing, deployment, and profile
          validation.
        </p>
      </header>

      <section className="card">
        <h2>Current project</h2>
        <AsyncSection state={project} onRetry={project.reload}>
          {(data) => <ProjectSummary project={data} />}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Asset Profile</h2>
        {/* Wait for the load before rendering the editor so the empty create
            form never flashes in front of an already-persisted profile. */}
        <AsyncSection state={storedProfile} onRetry={storedProfile.reload}>
          {() => (
            <ProfileEditor
              createdProfile={profile}
              onProfileCreated={setCreatedProfile}
            />
          )}
        </AsyncSection>
      </section>

      <section className="card">
        <h2>Deployment</h2>
        {/* No onDeployed callback: deployment is an operator CLI/bootstrap
            step, so this section only reports status — the effect above polls
            GET /project until it reaches a terminal state. */}
        <DeploymentSection
          deployStatus={deployStatus}
          deployNote={deployNote}
          profileLoading={storedProfile.status === "loading"}
        />
      </section>
    </div>
  );
}

/**
 * Gates the Deployment area on the deploy lifecycle:
 * - not-yet-deployed or Failed → the operator-CLI runbook hint (plus the
 *   failure note, when there is one);
 * - Deploying/Verifying → an in-progress indicator, while the parent polls
 *   GET /project;
 * - Active → hidden (the deployed details live in "Current project"), with a
 *   small confirmation and any non-fatal verification note.
 *
 * Deployment is a CLI/bootstrap runbook step, not a web console action: every
 * program/mint address is provisioned independently by the operator (see
 * solana/README's "Deployment process"), and the server seeds the Project
 * record itself once bootstrap has run — there is no deploy transaction for
 * this console to broadcast. Setup still edits the Asset Profile above
 * regardless of deploy status.
 */
function DeploymentSection({
  deployStatus,
  deployNote,
  profileLoading,
}: {
  deployStatus: DeployStatus;
  deployNote: string;
  profileLoading: boolean;
}) {
  if (deployStatus === "unknown" || profileLoading) {
    return (
      <div className="async-state async-state--loading" role="status">
        Loading…
      </div>
    );
  }

  if (deployStatus === "Deploying" || deployStatus === "Verifying") {
    return (
      <div className="async-state async-state--loading" role="status">
        <p>Deployment in progress — {deployStatus}…</p>
        <p className="field__hint">
          This updates automatically until the deployment completes.
        </p>
      </div>
    );
  }

  if (deployStatus === "Active") {
    return (
      <div role="status">
        <p>
          Deployed — see <strong>Current project</strong> above for the live
          addresses and configuration.
        </p>
        {deployNote && (
          <p className="field__hint">Verification note: {deployNote}</p>
        )}
      </div>
    );
  }

  // not-deployed or Failed.
  return (
    <div>
      {deployStatus === "Failed" && (
        <div className="async-state async-state--error" role="alert">
          <p>
            Deployment failed{deployNote ? `: ${deployNote}` : "."} Review the
            bootstrap configuration and retry via the runbook below.
          </p>
        </div>
      )}
      <p className="field__hint">
        Deployment is an operator CLI step, not a web console action — every
        program and mint is provisioned independently via the bootstrap
        runbook. See <code className="mono">solana/README.md</code>,
        &quot;Deployment process&quot;, for the full sequence. Once bootstrap
        has run, this project appears as Active in{" "}
        <strong>Current project</strong> above.
      </p>
    </div>
  );
}

/** Fetches the stored profile, mapping the admin-only 404 (none yet) to null rather than an error. */
async function loadStoredProfile(
  signal: AbortSignal,
): Promise<StoredProfile | null> {
  try {
    return await api.getProfile({ signal });
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

/**
 * Maps a persisted StoredProfile onto the CreatedProfile the profile summary needs.
 * Prefers the server-derived identity fields; where those are absent, falls
 * back to reading them off the raw profile document (same fields the editor
 * extracts on create). Carries the raw JSON so the admin can see what's stored.
 */
function storedToCreatedProfile(stored: StoredProfile): CreatedProfile {
  const fromRaw = extractProfileFields(stored.profile);
  return {
    profileDigest: stored.profileDigest,
    cid: stored.cid ?? "",
    projectId: stored.projectId || fromRaw.projectId,
    tokenDecimals: stored.decimals ?? fromRaw.tokenDecimals,
    tokenUnit: stored.tokenUnit ?? fromRaw.tokenUnit,
    rawProfileJson: JSON.stringify(stored.profile, null, 2),
  };
}

function ProjectSummary({ project }: { project: Project }) {
  return (
    <dl className="tx-preview__grid">
      <div className="tx-preview__row">
        <dt>Project ID</dt>
        <dd>{project.projectId ?? "—"}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Version</dt>
        <dd>{project.version ?? "—"}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Chain ID</dt>
        <dd>{project.chainId ?? "—"}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Profile digest</dt>
        <dd>{project.profileDigest ?? "—"}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Paused</dt>
        <dd>{project.paused ? "Yes" : "No"}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Auditor</dt>
        <dd title={project.auditor}>{project.auditor}</dd>
      </div>
      <div className="tx-preview__row">
        <dt>Treasury</dt>
        <dd title={project.treasury}>{project.treasury}</dd>
      </div>
      {project.addresses &&
        Object.entries(project.addresses).map(([key, value]) => (
          <div className="tx-preview__row" key={key}>
            <dt>{key}</dt>
            <dd title={value}>{value}</dd>
          </div>
        ))}
    </dl>
  );
}

/** What Deployment needs from a persisted profile — sourced from it, never re-typed by hand. */
interface CreatedProfile {
  profileDigest: string;
  cid: string;
  projectId: string;
  tokenDecimals: number;
  tokenUnit: string;
  /** The raw profile JSON (pretty-printed), shown read-only so the admin can see what's persisted. */
  rawProfileJson?: string;
}

/** The Asset Profile format is pinned at 1.0 and the projectId is generated, so
 * neither is asked of the operator — they are supplied automatically on create
 * (see ProfileEditor). Only the descriptive fields and the per-asset schema are
 * entered by hand. */
const PROFILE_VERSION = "1.0";

/** Starter template for the per-asset JSON Schema — a minimal object schema the
 * operator fills in. Kept small on purpose; the schema is validated server-side
 * (closed dialect) when Validate is clicked. */
const DEFAULT_ASSET_SCHEMA = JSON.stringify(
  {
    type: "object",
    properties: {},
    required: [],
  },
  null,
  2,
);

/** Best-effort client-side read of the fields Deployment needs — the server is the actual source of truth for the stored digest. */
function extractProfileFields(parsed: unknown): {
  projectId: string;
  tokenDecimals: number;
  tokenUnit: string;
} {
  const obj = (parsed && typeof parsed === "object" ? parsed : {}) as Record<
    string,
    unknown
  >;
  return {
    projectId: typeof obj.projectId === "string" ? obj.projectId : "",
    tokenDecimals:
      typeof obj.tokenDecimals === "number" ? obj.tokenDecimals : 0,
    tokenUnit: typeof obj.tokenUnit === "string" ? obj.tokenUnit : "",
  };
}

function ProfileEditor({
  createdProfile,
  onProfileCreated,
}: {
  createdProfile: CreatedProfile | null;
  onProfileCreated: (profile: CreatedProfile) => void;
}) {
  // profileVersion is pinned and projectId comes from the server config (the
  // operator sets contract.project_id before running the platform) — neither is
  // asked of the operator here. We read the projectId from GET /api/v1/config so
  // it matches the value the server gates every profile against. The rest are
  // entered as discrete, labelled fields rather than as one hand-authored JSON
  // blob.
  const [projectId, setProjectId] = useState<string | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [assetType, setAssetType] = useState("");
  const [tokenUnit, setTokenUnit] = useState("");
  const [tokenDecimals, setTokenDecimals] = useState(18);
  const [recordIdLabel, setRecordIdLabel] = useState("");
  const [assetSchemaJson, setAssetSchemaJson] = useState(DEFAULT_ASSET_SCHEMA);
  const [result, setResult] = useState<ValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const [creating, setCreating] = useState(false);

  // Load the deployment's projectId from the server. An empty value means the
  // operator has not set contract.project_id yet — profile creation is blocked
  // until they do, since the server would reject a mismatched (or missing) one.
  useEffect(() => {
    let cancelled = false;
    api
      .getConfig()
      .then((cfg) => {
        if (cancelled) return;
        if (cfg.projectId) {
          setProjectId(cfg.projectId);
        } else {
          setConfigError(
            "The server has no project_id configured. Set contract.project_id in the server config, restart the platform, then reload this page before creating a profile.",
          );
        }
      })
      .catch(() => {
        if (!cancelled)
          setConfigError(
            "Couldn't load the server configuration to read the projectId. Check the server is running and reload.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, []);

  /** Assembles the full profile document from the discrete fields, parsing the
   * only free-form part (assetSchema). The server is the source of truth for
   * validity — this just gets a well-formed object onto the wire. */
  function buildProfileOrError(): Record<string, unknown> | undefined {
    if (!projectId) {
      setError(
        "No projectId is configured on the server yet — set contract.project_id in the server config before creating a profile.",
      );
      return undefined;
    }
    let assetSchema: unknown;
    try {
      assetSchema = JSON.parse(assetSchemaJson);
    } catch {
      setError("Asset schema must be valid JSON.");
      return undefined;
    }
    return {
      profileVersion: PROFILE_VERSION,
      projectId,
      assetType,
      tokenUnit,
      tokenDecimals: Number(tokenDecimals),
      recordIdLabel,
      assetSchema,
    };
  }

  async function handleValidate() {
    setError(null);
    setResult(null);
    const built = buildProfileOrError();
    if (built === undefined) return;
    setValidating(true);
    try {
      setResult(await api.validateProfile(built as Record<string, never>));
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Validation request failed.",
      );
    } finally {
      setValidating(false);
    }
  }

  async function handleCreate() {
    setError(null);
    const built = buildProfileOrError();
    if (built === undefined) return;
    setCreating(true);
    try {
      const created = await api.createProfile(
        built as Record<string, never>,
        `create-profile-${projectId}`,
      );
      onProfileCreated({
        profileDigest: created.profileDigest ?? "",
        cid: created.cid ?? "",
        ...extractProfileFields(built),
        rawProfileJson: JSON.stringify(built, null, 2),
      });
    } catch (err) {
      if (err instanceof ApiError) {
        // POST /api/v1/profile's 400 body is a ValidationResult (errors[]),
        // not the generic Error{code,message} every other endpoint uses —
        // read whichever shape actually came back.
        const body = err.body as unknown as
          Partial<ValidationResult> | undefined;
        setError(
          body?.errors && body.errors.length > 0
            ? `Profile invalid: ${body.errors.join("; ")}`
            : (err.message ?? "Profile creation failed."),
        );
      } else {
        setError("Profile creation failed.");
      }
    } finally {
      setCreating(false);
    }
  }

  if (createdProfile) {
    return (
      <div>
        <dl className="tx-preview__grid" role="status">
          <div className="tx-preview__row">
            <dt>Status</dt>
            <dd>Persisted — immutable for the life of this deployment</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Project ID</dt>
            <dd>{createdProfile.projectId}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Token unit</dt>
            <dd>{createdProfile.tokenUnit}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Token decimals</dt>
            <dd>{createdProfile.tokenDecimals}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>Profile digest</dt>
            <dd className="mono">{createdProfile.profileDigest}</dd>
          </div>
          <div className="tx-preview__row">
            <dt>IPFS CID</dt>
            <dd className="mono">{createdProfile.cid}</dd>
          </div>
        </dl>
        {createdProfile.rawProfileJson && (
          <div className="field u-mt-4">
            <label htmlFor="stored-profile-json">
              Stored Asset Profile JSON
            </label>
            <textarea
              id="stored-profile-json"
              rows={12}
              className="mono"
              readOnly
              value={createdProfile.rawProfileJson}
              aria-describedby="stored-profile-json-hint"
            />
            <span className="field__hint" id="stored-profile-json-hint">
              This profile is persisted and immutable for the life of the
              deployment — shown read-only.
            </span>
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      {configError && (
        <p className="async-state--error" role="alert">
          {configError}
        </p>
      )}
      <dl className="tx-preview__grid">
        <div className="tx-preview__row">
          <dt>Project ID</dt>
          <dd className="mono">{projectId ?? "— not configured —"}</dd>
        </div>
      </dl>
      <p className="field__hint">
        The project ID (a UUID) comes from the server configuration
        (contract.project_id) and the profile version (1.0) is fixed — you
        don&apos;t enter either. If the project ID shows &quot;not
        configured&quot;, set it in the server config before creating a profile.
      </p>

      <div className="field">
        <label htmlFor="assetType">Asset type</label>
        <input
          id="assetType"
          value={assetType}
          onChange={(e) => setAssetType(e.target.value)}
          aria-describedby="assetType-hint"
        />
        <span className="field__hint" id="assetType-hint">
          The class of real-world asset this token represents (e.g. gold,
          real-estate, invoice). 1–128 characters.
        </span>
      </div>

      <div className="field">
        <label htmlFor="tokenUnit">Token unit</label>
        <input
          id="tokenUnit"
          value={tokenUnit}
          onChange={(e) => setTokenUnit(e.target.value)}
          aria-describedby="tokenUnit-hint"
        />
        <span className="field__hint" id="tokenUnit-hint">
          The unit one whole token stands for (e.g. gram, sqft, USD). 1–64
          characters.
        </span>
      </div>

      <div className="field">
        <label htmlFor="tokenDecimals">Token decimals</label>
        <input
          id="tokenDecimals"
          type="number"
          min={0}
          max={36}
          value={tokenDecimals}
          onChange={(e) => setTokenDecimals(Number(e.target.value))}
          aria-describedby="tokenDecimals-hint"
        />
        <span className="field__hint" id="tokenDecimals-hint">
          How many fractional digits the token supports (0–36; e.g. 9, like
          most SPL tokens). This is fixed on-chain at deploy.
        </span>
      </div>

      <div className="field">
        <label htmlFor="recordIdLabel">Record ID label</label>
        <input
          id="recordIdLabel"
          value={recordIdLabel}
          onChange={(e) => setRecordIdLabel(e.target.value)}
          aria-describedby="recordIdLabel-hint"
        />
        <span className="field__hint" id="recordIdLabel-hint">
          What each asset record&apos;s identifier means (e.g. Serial number,
          Deed number, Invoice ID). Shown in record forms. 1–128 characters.
        </span>
      </div>

      <div className="field">
        <label htmlFor="assetSchema">Asset schema</label>
        <textarea
          id="assetSchema"
          rows={10}
          className="mono"
          value={assetSchemaJson}
          onChange={(e) => setAssetSchemaJson(e.target.value)}
          aria-describedby="assetSchema-hint"
        />
        <span className="field__hint" id="assetSchema-hint">
          A JSON Schema describing the metadata each asset record must provide —
          it&apos;s what the metadata form is generated from and validated
          against. Enter a JSON Schema object (a restricted dialect is enforced
          server-side on Validate).{" "}
          <a
            href="https://json-schema.org/learn/getting-started-step-by-step"
            target="_blank"
            rel="noopener noreferrer"
          >
            JSON Schema documentation
          </a>
          . Paste the profile document you authored before the bootstrap — its
          digest was committed on-chain at that point and cannot change. Validate
          first (pure — no persistence). Creating is admin-only and permanent:
          once stored, a profile cannot be edited or replaced, and a document
          that doesn&apos;t hash to the on-chain digest is refused rather than
          stored.
        </span>
      </div>

      <button
        type="button"
        className="button button--secondary"
        onClick={handleValidate}
        disabled={!projectId || validating || creating}
      >
        {validating ? "Validating…" : "Validate profile"}
      </button>
      <button
        type="button"
        className="button button--primary"
        onClick={handleCreate}
        disabled={!projectId || !result?.valid || validating || creating}
      >
        {creating ? "Creating…" : "Create & persist profile"}
      </button>

      {error && (
        <p className="async-state--error" role="alert">
          {error}
        </p>
      )}

      {result && (
        <dl className="tx-preview__grid u-mt-4" role="status">
          <div className="tx-preview__row">
            <dt>Valid</dt>
            <dd>{result.valid ? "Yes" : "No"}</dd>
          </div>
          {result.profileDigest && (
            <div className="tx-preview__row">
              <dt>Profile digest</dt>
              <dd>{result.profileDigest}</dd>
            </div>
          )}
          {result.cid && (
            <div className="tx-preview__row">
              <dt>IPFS CID</dt>
              <dd>{result.cid}</dd>
            </div>
          )}
          {result.errors && result.errors.length > 0 && (
            <div className="tx-preview__row">
              <dt>Errors</dt>
              <dd>
                <ul>
                  {result.errors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </dd>
            </div>
          )}
        </dl>
      )}
    </div>
  );
}

