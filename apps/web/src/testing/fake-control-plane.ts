// A fetch-level fake of the RANGE API routes the flow uses.
//
// TEST-ONLY. It exists so `range-flow.test.ts` can drive the REAL api client through the whole
// vertical slice on every PR without a control plane, a worker or Docker.
//
// It models the parts of the contract that the client can get wrong:
//
//   - lifecycle: draft -> deploying -> ready -> resetting -> ready -> destroying -> destroyed
//   - 202 + BACKGROUND work. A mutation does not change the state synchronously; the state
//     advances only after `workerTicks` subsequent polls, so a client that assumes the mutation's
//     response is the new truth fails here.
//   - THE PRE-PLAN WINDOW: immediately after the 202 the operation is `pending` with
//     `total_steps: 0`, because the API cannot plan an operation it is not permitted to hold a
//     provider for. The worker fills the plan in on a later poll. A progress bar dividing by
//     `total_steps` divides by zero here.
//   - `unproven` teardown: `failTeardownProbe` makes destroy land in `recovery_required` with an
//     `unproven` residue verdict rather than in `destroyed`.
//
// WHAT IT CANNOT DO, stated so nobody mistakes a green run for more than it is: this fake is this
// repo's BELIEF about the server. If the real API changes, the fake keeps agreeing with the client
// and the gate stays green. Only the live run can catch that. Its fidelity is pinned by
// `range-contract.test.ts`, which checks the fake's enums against the frozen contract's.

interface FakeOperation {
  id: string;
  range_id: string;
  kind: string;
  status: string;
  phase: string | null;
  completed_steps: number;
  total_steps: number;
  percent: number;
  failure_code: string | null;
  failure_message: string | null;
  started_at: string;
  finished_at: string | null;
  steps: { key: string; label: string; status: string; detail: string | null; at: string | null }[];
}

export interface FakeRangeApiOptions {
  /** Polls the worker takes to plan the operation, then to finish it. */
  workerTicks?: number;
  /** Make the teardown probe unreachable, so destroy lands in recovery_required. */
  failTeardownProbe?: boolean;
  /** Make deploy fail rather than succeed. */
  failDeploy?: boolean;
}

export interface FakeRangeApi {
  fetch: typeof fetch;
  /** Every request the client made, as "METHOD /path" — proves call order. */
  calls: string[];
  /** Event kinds recorded so far, in order. */
  eventKinds: () => string[];
}

const COMPONENTS = [
  { key: "juice-shop", name: "OWASP Juice Shop", role: "target", image: "bkimminich/juice-shop:v17.1.0", container_port: 3000, protocol: "http", path: "/" },
  { key: "dvwa", name: "DVWA", role: "target", image: "vulnerables/web-dvwa:1.9", container_port: 80, protocol: "http", path: "/" },
  { key: "scorer", name: "Scoring probe", role: "scoring", image: "secp/scorer:1", container_port: null, protocol: "http", path: "/" },
];

export function createFakeRangeApi(opts: FakeRangeApiOptions = {}): FakeRangeApi {
  const workerTicks = opts.workerTicks ?? 1;
  const calls: string[] = [];

  let seq = 0;
  const nextId = (p: string) => `${p}-${String(++seq).padStart(4, "0")}`;
  // A fixed clock so event ordering is deterministic.
  let tick = 0;
  const now = () => {
    tick += 1;
    return `2026-08-05T00:00:${String(tick).padStart(2, "0")}`;
  };

  const templates = [
    {
      slug: "web-breach-lab",
      name: "Web Breach Lab",
      summary: "Two intentionally vulnerable web applications on an isolated Docker network.",
      description: "Longer prose for the detail pane.",
      provider: "local_docker",
      difficulty: "beginner",
      estimated_deploy_seconds: 180,
      warning: "Contains intentionally vulnerable software. Ephemeral local Docker only.",
      components: COMPONENTS,
      challenge_count: 6,
      total_points: 600,
    },
  ];

  interface FakeRange {
    id: string;
    name: string;
    template_slug: string;
    template_name: string;
    provider: string;
    state: string;
    state_reason: string | null;
    created_at: string;
    updated_at: string;
    deployed_at: string | null;
    destroyed_at: string | null;
    competition_id: string | null;
    residue_verdict: string | null;
    access: unknown[];
  }

  let range: FakeRange | null = null;
  let operation: FakeOperation | null = null;
  /** Polls remaining before the worker advances the current operation. */
  let ticksLeft = 0;
  /** Whether the worker has planned the current operation yet. */
  let planned = false;
  let resources: Record<string, unknown>[] = [];
  const events: { id: string; range_id: string; sequence: number; kind: string; level: string; message: string; data: Record<string, unknown>; occurred_at: string }[] = [];
  const teardowns: Record<string, unknown>[] = [];

  const emit = (kind: string, message: string, level = "info") => {
    events.push({
      id: nextId("evt"),
      range_id: range?.id ?? "",
      sequence: events.length + 1,
      kind,
      level,
      message,
      data: {},
      occurred_at: now(),
    });
  };

  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const error = (status: number, code: string, message: string): Response =>
    json({ error: { code, message } }, status);

  const startOperation = (kind: string): FakeOperation => {
    // The 202 window: pending, NO PLAN. total_steps is 0 because the API cannot plan an operation
    // it may not hold a provider for.
    operation = {
      id: nextId("op"),
      range_id: range?.id ?? "",
      kind,
      status: "pending",
      phase: null,
      completed_steps: 0,
      total_steps: 0,
      percent: 0,
      failure_code: null,
      failure_message: null,
      started_at: now(),
      finished_at: null,
      steps: [],
    };
    planned = false;
    ticksLeft = workerTicks;
    return operation;
  };

  const planSteps = (kind: string) => {
    if (operation === null) return;
    const labels =
      kind === "deploy"
        ? ["Create isolated network", "Pull OWASP Juice Shop", "Start OWASP Juice Shop", "Verify OWASP Juice Shop responds"]
        : kind === "reset"
          ? ["Recreate target containers", "Verify targets respond"]
          : ["Remove containers", "Remove network", "Verify removal"];
    operation.status = "running";
    operation.phase = kind === "deploy" ? "create" : kind;
    operation.total_steps = labels.length;
    operation.steps = labels.map((label, i) => ({
      key: `${kind}-${i}`,
      label,
      status: "pending",
      detail: null,
      at: null,
    }));
    planned = true;
  };

  const finishOperation = (kind: string) => {
    if (operation === null || range === null) return;
    const unproven = kind === "destroy" && opts.failTeardownProbe === true;
    const failed = kind === "deploy" && opts.failDeploy === true;

    operation.completed_steps = operation.total_steps;
    operation.percent = failed || unproven ? operation.percent : 100;
    operation.status = failed ? "failed" : unproven ? "unproven" : "succeeded";
    operation.finished_at = now();
    operation.steps = operation.steps.map((s) => ({
      ...s,
      status: failed ? "failed" : unproven ? "unproven" : "succeeded",
      at: now(),
    }));
    if (failed) {
      operation.failure_code = "range_provider_unavailable";
      operation.failure_message = "provider unreachable";
    }

    if (kind === "deploy") {
      if (failed) {
        range.state = "failed";
        range.state_reason = "The provider could not be reached.";
        emit("deploy_failed", "Deployment failed", "error");
      } else {
        emit("network_created", "Created the isolated network secp-range-fake");
        resources = [
          { id: nextId("res"), kind: "network", provider: "local_docker", component_key: null, name: "secp-range-net", external_id: "net123", image: null, image_digest: null, state: "verified", host_port: null, created_at: now(), removed_at: null, detail: {} },
          ...COMPONENTS.filter((c) => c.container_port !== null).map((c, i) => ({
            id: nextId("res"),
            kind: "container",
            provider: "local_docker",
            component_key: c.key,
            name: `secp-range-${c.key}`,
            external_id: `ctr${i}`,
            image: c.image,
            image_digest: `sha256:dead${i}`,
            state: "verified",
            host_port: 34010 + i,
            created_at: now(),
            removed_at: null,
            detail: {},
          })),
        ];
        range.state = "ready";
        range.deployed_at = now();
        range.access = COMPONENTS.filter((c) => c.container_port !== null).map((c, i) => ({
          component_key: c.key,
          name: c.name,
          url: `http://127.0.0.1:${34010 + i}/`,
          host: "127.0.0.1",
          port: 34010 + i,
          protocol: "http",
          reachable: true,
          observed_at: now(),
        }));
        for (const c of COMPONENTS.filter((x) => x.container_port !== null)) {
          emit("container_started", `Started ${c.name} as secp-range-fake-${c.key}`);
          emit("resource_verified", `${c.name} responded (HTTP 200)`);
        }
        emit("range_ready", "Range deployed; every component was observed responding");
      }
    } else if (kind === "reset") {
      range.state = "ready";
      emit("range_ready", "Range reset complete; every component was observed responding");
    } else {
      // Destroy. `unproven` lands in recovery_required, NOT destroyed — nobody proved it is gone.
      for (const r of resources) {
        r.state = unproven ? "unproven" : "removed";
        r.removed_at = unproven ? null : now();
      }
      range.access = [];
      range.state = unproven ? "recovery_required" : "destroyed";
      range.residue_verdict = unproven ? "unproven" : "clean";
      range.destroyed_at = unproven ? null : now();
      if (unproven) range.state_reason = "The teardown probe could not reach the provider.";
      teardowns.push({
        id: nextId("tev"),
        range_id: range.id,
        operation_id: operation.id,
        verdict: unproven ? "unproven" : "clean",
        probe_reachable: !unproven,
        expected_count: resources.length,
        removed_confirmed: unproven ? 0 : resources.length,
        still_present: 0,
        unproven_count: unproven ? resources.length : 0,
        reason: unproven
          ? "The removal and the existence check share a failure mode, so absence was not proved."
          : null,
        observed_at: now(),
        resources: resources.map((r) => ({
          kind: r.kind,
          name: r.name,
          external_id: r.external_id,
          verdict: unproven ? "unproven" : "removed",
          detail: null,
        })),
      });
      // `range_destroyed` is a kind captured from a real run. The unproven kind is NOT — that path
      // has not been observed against a live server, so nothing asserts on its name; the unproven
      // tests assert on STATE (`recovery_required`) and `residue_verdict`, which the contract does
      // pin. Naming an unverified kind here and then asserting it would rebuild the exact fiction
      // the live run just caught.
      emit(
        unproven ? "range_teardown_unproven" : "range_destroyed",
        unproven
          ? "Teardown could not be verified"
          : `Range destroyed; all ${resources.length} owned resource(s) confirmed absent`,
        unproven ? "warning" : "info",
      );
    }
    range.updated_at = now();
  };

  /** Advance the worker one poll. Called on every `GET /ranges/{id}`. */
  const advanceWorker = () => {
    if (operation === null || range === null) return;
    if (operation.status === "succeeded" || operation.status === "failed" || operation.status === "unproven") {
      return;
    }
    if (ticksLeft > 0) {
      ticksLeft -= 1;
      return;
    }
    if (!planned) {
      planSteps(operation.kind);
      ticksLeft = workerTicks;
      return;
    }
    finishOperation(operation.kind);
  };

  const summary = (op: FakeOperation | null) =>
    op === null
      ? null
      : {
          id: op.id,
          kind: op.kind,
          status: op.status,
          phase: op.phase,
          completed_steps: op.completed_steps,
          total_steps: op.total_steps,
          percent: op.percent,
        };

  const rangeOut = () =>
    range === null ? null : { ...range, current_operation: summary(operation) };

  const fakeFetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : String(input));
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(`${method} ${path}`);

    if (method === "GET" && path === "/api/v1/range-templates") return json(templates);
    const tplMatch = /^\/api\/v1\/range-templates\/([^/]+)$/.exec(path);
    if (method === "GET" && tplMatch !== null) {
      const t = templates.find((x) => x.slug === tplMatch[1]);
      return t === undefined ? error(404, "not_found", "template not found") : json(t);
    }

    if (method === "POST" && path === "/api/v1/ranges") {
      const body = JSON.parse(String(init?.body ?? "{}")) as { template_slug: string; name?: string };
      const t = templates.find((x) => x.slug === body.template_slug);
      if (t === undefined) return error(404, "not_found", "template not found");
      range = {
        id: nextId("rng"),
        name: body.name ?? t.name,
        template_slug: t.slug,
        template_name: t.name,
        provider: t.provider,
        state: "draft",
        state_reason: null,
        created_at: now(),
        updated_at: now(),
        deployed_at: null,
        destroyed_at: null,
        competition_id: null,
        residue_verdict: null,
        access: [],
      };
      operation = null;
      emit("range_created", `Range ${range.name} created`);
      return json(rangeOut(), 201);
    }

    if (method === "GET" && path === "/api/v1/ranges") return json(range === null ? [] : [rangeOut()]);

    const opMatch = /^\/api\/v1\/range-operations\/([^/]+)$/.exec(path);
    if (method === "GET" && opMatch !== null) {
      return operation === null || operation.id !== opMatch[1]
        ? error(404, "not_found", "operation not found")
        : json(operation);
    }

    const rngMatch = /^\/api\/v1\/ranges\/([^/]+)(\/.*)?$/.exec(path);
    if (rngMatch !== null) {
      if (range === null || range.id !== rngMatch[1]) {
        return error(404, "range_not_found", "range not found");
      }
      const tail = rngMatch[2] ?? "";

      if (method === "GET" && tail === "") {
        // Every poll advances the worker: this is what makes the state change asynchronously
        // rather than in the mutation's response.
        advanceWorker();
        return json(rangeOut());
      }
      if (method === "GET" && tail === "/resources") return json(resources);
      if (method === "GET" && tail === "/operations") return json(operation === null ? [] : [operation]);
      if (method === "GET" && tail === "/teardown-evidence") return json([...teardowns].reverse());
      if (method === "GET" && tail === "/events") {
        const after = url.searchParams.get("after_sequence");
        const from = after === null ? 0 : Number(after);
        return json(events.filter((e) => e.sequence > from));
      }

      const action = /^\/(deploy|reset|destroy)$/.exec(tail);
      if (method === "POST" && action !== null) {
        const kind = action[1];
        const allowed =
          kind === "deploy"
            ? ["draft", "failed"]
            : kind === "reset"
              ? ["ready", "active", "failed"]
              : ["draft", "deploying", "ready", "active", "resetting", "failed", "recovery_required"];
        if (!allowed.includes(range.state)) {
          return error(409, "range_invalid_transition", `cannot ${kind} from ${range.state}`);
        }
        const op = startOperation(kind);
        range.state = kind === "deploy" ? "deploying" : kind === "reset" ? "resetting" : "destroying";
        range.updated_at = now();
        // Verified kinds: deploy_requested / reset_requested / destroy_requested.
        emit(`${kind}_requested`, `${kind} requested`);
        return json(op, 202);
      }
    }

    return error(404, "not_found", `fake range API has no route for ${method} ${path}`);
  };

  return { fetch: fakeFetch, calls, eventKinds: () => events.map((e) => e.kind) };
}
