import "./readonly-ops.css";

import { useEffect, useState } from "react";

import { api } from "../api/client";
import type {
  BootstrapScript,
  BootstrapSession,
  ExecutionTarget,
  WorkerDiscoveryNode,
} from "../api/types";
import {
  ClosedCodeError,
  CyberButton,
  CyberCard,
  CyberInput,
  CyberSelect,
  HashChip,
  SafetyNotice,
  StatusBadge,
  StepRail,
  useAction,
} from "../components/ui";
import { RiveWorkerBundle } from "../components/rive/wrappers";
import { useAsync } from "../hooks";
import {
  BOOTSTRAP_ERROR_TEXT,
  BOOTSTRAP_RESPONSIBILITY,
  READY_TO_QUEUE_NOTICE,
  WORKER_BUNDLE_OWNERSHIP_NOTICE,
  bootstrapStepItems,
  type Responsibility,
} from "./readonly-ops";
import {
  READ_ONLY_BOOTSTRAP_INTRO,
  SCRIPT_ACTIONS,
  STEP_LABELS,
  WORKER_NOT_API_NOTICE,
  WORKER_SIDE_PREREQUISITES,
  bootstrapStatusLabel,
  currentStep,
  matchWorkerNodeByPublicKeyFingerprint,
  validateNodeIdentityReview,
  validateFingerprint,
  validatePublicKey,
} from "./read-only-bootstrap";

const RESP_CLASS: Record<Responsibility, string> = {
  App: "rops-resp--app",
  Worker: "rops-resp--worker",
  "Proxmox host": "rops-resp--host",
  "Human operator": "",
};

function RespBadge({ who }: { who: Responsibility }) {
  return <span className={`rops-resp ${RESP_CLASS[who]}`}>{who}</span>;
}

export function ReadOnlyBootstrap() {
  const targets = useAsync<ExecutionTarget[]>(() => api.listTargets(), []);
  // SECP-B8: the worker OWNS + generates its keypair and publishes only the
  // PUBLIC key — the operator never runs ssh-keygen. This drives auto-populate.
  const workerNodes = useAsync<WorkerDiscoveryNode[]>(() => api.listWorkerNodes(), []);
  const bootstrapSessions = useAsync<BootstrapSession[]>(
    () => api.listBootstrapSessions(),
    [],
  );
  const [session, setSession] = useState<BootstrapSession | null>(null);
  const [script, setScript] = useState<BootstrapScript | null>(null);
  const [targetId, setTargetId] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [proof, setProof] = useState("");
  const [selectedWorkerNodeId, setSelectedWorkerNodeId] = useState("");
  const [deploymentBinding, setDeploymentBinding] = useState("");
  const [reviewProofId, setReviewProofId] = useState("");
  const [reviewIssuer, setReviewIssuer] = useState("");
  const [deploymentBindingReviewed, setDeploymentBindingReviewed] = useState(false);
  const [verificationAnchorReviewed, setVerificationAnchorReviewed] = useState(false);
  const [rotationRevocationReviewed, setRotationRevocationReviewed] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction({ codeText: BOOTSTRAP_ERROR_TEXT });

  const step = currentStep(session);
  const keyCheck = validatePublicKey(publicKey);
  const fpCheck = validateFingerprint(fingerprint);
  const proxmoxTargets = (targets.data ?? []).filter((t) => t.plugin_name === "proxmox");
  const nodes = workerNodes.data ?? [];
  const selectedWorkerNode = nodes.find((node) => node.id === selectedWorkerNodeId);
  const sessionNodeMatch = session
    ? matchWorkerNodeByPublicKeyFingerprint(
        nodes,
        session.worker_ssh_public_key_fingerprint,
      )
    : null;
  const identityReview = {
    deploymentBinding,
    proofId: reviewProofId,
    issuer: reviewIssuer,
    deploymentBindingReviewed,
    verificationAnchorReviewed,
    rotationRevocationReviewed,
  };
  const identityReviewCheck = validateNodeIdentityReview(identityReview);
  const resumableSessions = (bootstrapSessions.data ?? []).filter(
    (candidate) => ["pending", "completed", "bound"].includes(candidate.status),
  );
  const railItems = bootstrapStepItems(STEP_LABELS, session);

  // A selected id is convenient while the page stays open. A resumed/reloaded server session is
  // instead rebound from its authoritative SSH public-key fingerprint. Zero or multiple matches
  // clear the selection and keep approval/binding disabled.
  useEffect(() => {
    if (!session || !workerNodes.data) return;
    const match = matchWorkerNodeByPublicKeyFingerprint(
      workerNodes.data,
      session.worker_ssh_public_key_fingerprint,
    );
    if (match.ok) {
      setSelectedWorkerNodeId(match.node.id);
      setPublicKey(match.node.ssh_public_key);
    } else {
      setSelectedWorkerNodeId("");
    }
  }, [session, workerNodes.data]);

  const create = () =>
    action.run(async () => {
      const s = await api.createBootstrapSession({
        execution_target_id: targetId,
        worker_ssh_public_key: publicKey.trim(),
      });
      setScript(await api.getBootstrapScript(s.id));
      setSession(s);
    });

  const complete = () =>
    action.run(async () => {
      if (!session) return;
      setSession(
        await api.completeBootstrapSession(session.id, {
          host_key_fingerprint: fingerprint.trim(),
          proof_text: proof.trim() || null,
        }),
      );
    });

  const resume = (sessionId: string) =>
    action.run(async () => {
      const resumed = await api.getBootstrapSession(sessionId);
      setScript(
        resumed.status === "pending" ? await api.getBootstrapScript(resumed.id) : null,
      );
      setSession(resumed);
    });

  const bind = () =>
    action.run(async () => {
      if (!session) return;
      const match = matchWorkerNodeByPublicKeyFingerprint(
        nodes,
        session.worker_ssh_public_key_fingerprint,
      );
      if (!match.ok || !identityReviewCheck.ok) return;
      const linked = await api.reviewAndLinkWorkerNode(match.node.id, {
        expected_node_revision: match.node.revision,
        expected_ssh_public_key_fingerprint: match.node.ssh_public_key_fingerprint,
        expected_admission_anchor_fingerprint:
          match.node.admission_anchor_fingerprint,
        deployment_binding: deploymentBinding,
        proof_id: reviewProofId,
        issuer: reviewIssuer,
        deployment_binding_review_confirmed: true,
        verification_anchor_review_confirmed: true,
        rotation_revocation_review_confirmed: true,
      });
      if (!linked.worker_identity_registration_id) return;
      setSession(await api.bindBootstrapSession(session.id));
    });

  // SECP-B8: guided target-admin action; the backend enforces
  // staging_substrate:manage and NEVER silently auto-grants.
  const grantEligibility = () =>
    action.run(async () => {
      if (!session) return;
      setNotice(null);
      await api.grantSubstrateEligibility(session.execution_target_id);
      setNotice(
        "Staging-substrate eligibility granted. You can now create the live-read authorization.",
      );
    });

  function applyWorkerNode(node: WorkerDiscoveryNode) {
    setSelectedWorkerNodeId(node.id);
    setPublicKey(node.ssh_public_key);
    setNotice(
      `Using the worker's published PUBLIC key (fingerprint ${node.ssh_public_key_fingerprint}). ` +
        "The worker owns the private key — you never handle it.",
    );
  }

  const copyScript = () => {
    if (script) void navigator.clipboard?.writeText(script.script);
  };

  return (
    <div className="rops">
      <div className="rops-head">
        <h1>Prepare Proxmox Read-Only Bootstrap</h1>
        <p className="rops-intro">{READ_ONLY_BOOTSTRAP_INTRO}</p>
      </div>
      <SafetyNotice role="note" tone="warn">
        {WORKER_NOT_API_NOTICE}
      </SafetyNotice>

      <div className="rops-grid">
        <div style={{ display: "grid", gap: 14 }}>
          {action.error && (
            <ClosedCodeError
              error={{ code: action.error.code, message: "" }}
              codeText={BOOTSTRAP_ERROR_TEXT}
              onDismiss={action.clearError}
            />
          )}
          {notice && (
            <SafetyNotice role="status" tone="info">
              {notice}
            </SafetyNotice>
          )}

          {!session && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS.create}</h3>
                <RespBadge who={BOOTSTRAP_RESPONSIBILITY.create} />
              </div>
              {resumableSessions.length > 0 && (
                <CyberSelect
                  label="Resume an existing bootstrap session"
                  value=""
                  onChange={(event) => {
                    if (event.target.value) void resume(event.target.value);
                  }}
                  options={[
                    { value: "", label: "Select a session to resume..." },
                    ...resumableSessions.map((candidate) => ({
                      value: candidate.id,
                      label: `${candidate.status} (${candidate.id.slice(0, 8)})`,
                    })),
                  ]}
                />
              )}
              <CyberSelect
                label="Proxmox target"
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                options={[
                  { value: "", label: "Select an active-onboarded proxmox target…" },
                  ...proxmoxTargets.map((t) => ({ value: t.id, label: t.display_name })),
                ]}
              />
              <p className="rops-note">
                <strong>Worker public key</strong> — the worker generates and owns its
                SSH keypair; the app surfaces only the PUBLIC key. You never run{" "}
                <code>ssh-keygen</code> or handle a private key.
              </p>
              {nodes.length > 0 ? (
                <CyberSelect
                  label="Use a published worker's public key"
                  value={selectedWorkerNodeId}
                  onChange={(e) => {
                    const n = nodes.find((x) => x.id === e.target.value);
                    if (n) {
                      applyWorkerNode(n);
                    } else {
                      setSelectedWorkerNodeId("");
                      setPublicKey("");
                    }
                  }}
                  options={[
                    { value: "", label: "Select a worker node…" },
                    ...nodes.map((n) => ({
                      value: n.id,
                      label: `${n.node_label} (${n.ssh_public_key_fingerprint})`,
                    })),
                  ]}
                />
              ) : (
                <SafetyNotice role="note" tone="info">
                  No worker has published a public key yet. Enable the worker-managed
                  discovery profile (<code>SECP_DISCOVERY_WORKER_MANAGED_BUNDLE=true</code>)
                  — the worker will generate its keypair and publish its PUBLIC key here
                  automatically. Binding remains unavailable until one published node is selected.
                </SafetyNotice>
              )}
              <label className="rops-note" htmlFor="worker-public-key">
                Worker SSH PUBLIC key (never a private key)
              </label>
              <textarea
                id="worker-public-key"
                rows={2}
                value={publicKey}
                placeholder="ssh-ed25519 AAAA... worker@secp"
                readOnly
              />
              {publicKey && !keyCheck.ok && (
                <p className="ui-field__error">{keyCheck.message}</p>
              )}
              <div style={{ marginTop: 10 }}>
                <CyberButton
                  disabled={
                    action.busy || !targetId || !selectedWorkerNode || !keyCheck.ok
                  }
                  onClick={create}
                >
                  Generate bootstrap script
                </CyberButton>
              </div>
            </CyberCard>
          )}

          {session && script && step === "run-script" && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS["run-script"]}</h3>
                <RespBadge who={BOOTSTRAP_RESPONSIBILITY["run-script"]} />
              </div>
              <p className="rops-note">
                The generated script is the only host-side manual action. Run it once as
                root on the Proxmox host. It will:
              </p>
              <ul className="rops-checklist">
                {SCRIPT_ACTIONS.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ul>
              <div className="rops-copyrow">
                <CyberButton
                  variant="secondary"
                  size="sm"
                  aria-label="Copy the generated bootstrap script"
                  onClick={copyScript}
                >
                  Copy script
                </CyberButton>
              </div>
              <pre className="rops-script" data-testid="bootstrap-script">
                {script.script}
              </pre>
            </CyberCard>
          )}

          {session && (step === "run-script" || step === "bind") && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS.complete}</h3>
                <RespBadge who={BOOTSTRAP_RESPONSIBILITY.complete} />
              </div>
              <CyberInput
                label="Host SSH key fingerprint (from the proof / ssh-keygen -lf)"
                value={fingerprint}
                placeholder="SHA256:…"
                errorText={fingerprint && !fpCheck.ok ? fpCheck.message : undefined}
                onChange={(e) => setFingerprint(e.target.value)}
              />
              <label className="rops-note" htmlFor="bootstrap-proof">
                Bounded proof (paste the full SECPDISC-PROOF block)
              </label>
              <textarea
                id="bootstrap-proof"
                rows={3}
                value={proof}
                onChange={(e) => setProof(e.target.value)}
              />
              <p className="rops-note">
                Paste the whole proof block. It carries the host's PUBLIC key line, which
                the worker uses to pin <code>known_hosts</code> and assemble its bundle
                automatically — no manual bundle files. The host proof and public host key
                are distinct from the worker's identity.
              </p>
              <div style={{ marginTop: 6 }}>
                <CyberButton
                  variant="ok"
                  size="sm"
                  disabled={action.busy || !fpCheck.ok || session.status !== "pending"}
                  onClick={complete}
                >
                  Confirm bootstrap
                </CyberButton>
              </div>
            </CyberCard>
          )}

          {session && step === "bind" && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS.bind}</h3>
                <RespBadge who={BOOTSTRAP_RESPONSIBILITY.bind} />
              </div>
              <p className="rops-note">
                Endpoint binding digest computed. First perform the explicit worker identity
                review for the exact published node, then create the separately-approved
                live-read authorization for this exact endpoint. Publication alone grants
                nothing.
              </p>
              {sessionNodeMatch?.ok ? (
                <SafetyNotice role="status" tone="info">
                  Matched published node <strong>{sessionNodeMatch.node.node_label}</strong>
                  {" at revision "}
                  {sessionNodeMatch.node.revision}. Review its SSH public-key fingerprint{" "}
                  <HashChip
                    value={sessionNodeMatch.node.ssh_public_key_fingerprint}
                    digits={18}
                  />{" "}
                  and admission-anchor fingerprint{" "}
                  <HashChip
                    value={sessionNodeMatch.node.admission_anchor_fingerprint}
                    digits={18}
                  />
                  .
                </SafetyNotice>
              ) : (
                <SafetyNotice role="alert" tone="warn">
                  {sessionNodeMatch?.reason === "ambiguous"
                    ? "More than one published node matches this session's public-key fingerprint. Binding is refused until the ambiguity is removed."
                    : "No current published node matches this session's public-key fingerprint. Select or create a session for the current worker key."}
                </SafetyNotice>
              )}
              <CyberInput
                label="Deployment binding (opaque, non-secret)"
                value={deploymentBinding}
                placeholder="production-worker"
                onChange={(event) => setDeploymentBinding(event.target.value)}
              />
              <CyberInput
                label="Review proof ID (opaque, non-secret)"
                value={reviewProofId}
                placeholder="change-review-1234"
                onChange={(event) => setReviewProofId(event.target.value)}
              />
              <CyberInput
                label="Review issuer (opaque, non-secret)"
                value={reviewIssuer}
                placeholder="platform-operator"
                onChange={(event) => setReviewIssuer(event.target.value)}
              />
              <div className="rops-checklist">
                <label>
                  <input
                    type="checkbox"
                    checked={deploymentBindingReviewed}
                    onChange={(event) =>
                      setDeploymentBindingReviewed(event.target.checked)
                    }
                  />{" "}
                  I reviewed the opaque deployment binding for this worker node.
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={verificationAnchorReviewed}
                    onChange={(event) =>
                      setVerificationAnchorReviewed(event.target.checked)
                    }
                  />{" "}
                  I reviewed the exact published admission-anchor fingerprint above.
                </label>
                <label>
                  <input
                    type="checkbox"
                    checked={rotationRevocationReviewed}
                    onChange={(event) =>
                      setRotationRevocationReviewed(event.target.checked)
                    }
                  />{" "}
                  I reviewed key rotation. If a current same-label identity uses the old
                  anchor, revoke it before approving this one.
                </label>
              </div>
              {!identityReviewCheck.ok && (
                <p className="ui-field__error">{identityReviewCheck.message}</p>
              )}
              <CyberButton
                variant="secondary"
                size="sm"
                disabled={
                  action.busy ||
                  sessionNodeMatch?.ok !== true ||
                  !identityReviewCheck.ok
                }
                onClick={bind}
              >
                Approve worker identity and create live-read authorization
              </CyberButton>
              <details className="rops-disclosure" data-testid="substrate-grant">
                <summary>Target not staging-substrate eligible?</summary>
                <p className="rops-note">
                  If creating the authorization fails with{" "}
                  <code>readonly_preflight_substrate_ineligible</code>, an operator with the{" "}
                  <code>staging_substrate:manage</code> capability can grant eligibility for
                  this target. It is never granted automatically.
                </p>
                <CyberButton
                  variant="secondary"
                  size="sm"
                  disabled={action.busy}
                  onClick={grantEligibility}
                >
                  Grant staging-substrate eligibility
                </CyberButton>
              </details>
            </CyberCard>
          )}

          {session && step === "run-discovery" && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS["run-discovery"]}</h3>
                <RespBadge who={BOOTSTRAP_RESPONSIBILITY["run-discovery"]} />
                {/* This step only renders once the session is bound, so the
                    worker-owned bundle is prepared. "ready" means prepared,
                    not that discovery ran. */}
                <RiveWorkerBundle
                  ready={session.status === "bound"}
                  label="Worker bundle"
                  size={22}
                />
                <StatusBadge state={session.status} domain="bootstrap" />
              </div>
              <p data-testid="bootstrap-bound">
                <strong>{bootstrapStatusLabel(session.status)}.</strong> This target is
                bound to an approved live-read authorization.
              </p>
              {session.endpoint_binding_hash && (
                <p className="rops-binding">
                  <span className="muted">endpoint binding digest</span>
                  <HashChip value={session.endpoint_binding_hash} digits={18} />
                </p>
              )}
              <SafetyNotice role="note" tone="info">
                {WORKER_BUNDLE_OWNERSHIP_NOTICE}
              </SafetyNotice>
              <p className="rops-note">
                {READY_TO_QUEUE_NOTICE} Go to{" "}
                <a href="/target-discovery">Target Discovery</a> to run read-only discovery
                and review the candidate plan. Live deployment apply remains sealed.
              </p>
              <details className="rops-disclosure" data-testid="worker-side-prerequisites">
                <summary>
                  Discovery still can't reach the host? Check the worker-side prerequisites
                </summary>
                <p className="rops-note">
                  The control-plane steps are done. The remaining prerequisites live on the
                  WORKER (the app cannot observe them). If discovery fails with{" "}
                  <code>probe_source_sealed</code>, confirm:
                </p>
                <ul className="rops-checklist">
                  {WORKER_SIDE_PREREQUISITES.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </details>
            </CyberCard>
          )}

          {session && step === "refused" && (
            <CyberCard>
              <div className="rops-step-head">
                <h3 style={{ margin: 0 }}>{STEP_LABELS.refused}</h3>
                <StatusBadge state={session.status} domain="bootstrap" />
              </div>
              <SafetyNotice role="alert" tone="warn">
                This session is not authorized and cannot be used for discovery. Resume a
                different current session or create a new one for the worker's latest published
                public key.
              </SafetyNotice>
            </CyberCard>
          )}
        </div>

        <aside style={{ display: "grid", gap: 14 }}>
          <CyberCard heading="Gated sequence">
            <StepRail items={railItems} aria-label="Bootstrap steps" />
            <p className="rops-note">
              Each gate is independent and owned by App, Human operator, Worker, or the
              Proxmox host. A completed step never implies a later gate passed.
            </p>
          </CyberCard>
          {session && (
            <CyberCard surface="well" heading="Session posture">
              <StatusBadge state={session.status} domain="bootstrap" />
              <p className="rops-note">
                Bootstrap confirmation does not mean discovery ran; a bound authorization
                does not construct the collector; live apply remains sealed.
              </p>
            </CyberCard>
          )}
        </aside>
      </div>
    </div>
  );
}
