// A fetch-level fake of the control-plane routes the range flow uses.
//
// TEST-ONLY. It exists so `range-flow.test.ts` can drive the REAL api client through the whole
// vertical slice on every PR without a server.
//
// It models the lifecycle this repo observed the shipped API produce:
//
//   draft --validate--> validated --plan--> planned --submit--> awaiting_approval
//         --approve--> approved --deploy--> running --destroy--> destroyed
//
// and appends the same audit actions, including one `instance.created` per team.
//
// WHAT IT CANNOT DO, stated so nobody mistakes a green run for more than it is: this fake is this
// repo's BELIEF about the server. If the real API changes, the fake keeps agreeing with the client
// and the gate stays green. Only `range-flow.live-test.ts`, against a real control plane, can catch
// that. What this does catch is the client regressing — a dropped call, a reordered step, a
// mutation that stops refreshing what it changed.

interface FakeExercise {
  id: string;
  organization_id: string;
  template_id: string;
  environment_version_id: string;
  name: string;
  lifecycle_state: string;
  team_count: number;
  created_at: string;
}

interface FakePlan {
  id: string;
  exercise_id: string;
  status: string;
}

interface FakeInstance {
  id: string;
  exercise_id: string;
  team_index: number;
  team_ref: string;
  instance_ref: string;
  lifecycle_state: string;
  provider: string;
}

export interface FakeControlPlaneOptions {
  /** Teams the blueprint declares. Each produces one instance on deploy. */
  teamCount?: number;
  /** Targets declared per team in the topology. */
  targetsPerTeam?: number;
}

export interface FakeControlPlane {
  /** Install as `globalThis.fetch`. */
  fetch: typeof fetch;
  /** Every request the client made, as "METHOD /path" — proves call order. */
  calls: string[];
  /** The recorded audit ledger, oldest first. */
  auditActions: () => string[];
  /** Force the range into a state, for testing branches the happy path never reaches. */
  setState: (state: string) => void;
}

const ORG = "11111111-1111-1111-1111-111111111111";

export function createFakeControlPlane(
  opts: FakeControlPlaneOptions = {},
): FakeControlPlane {
  const teamCount = opts.teamCount ?? 2;
  const targetsPerTeam = opts.targetsPerTeam ?? 3;

  const calls: string[] = [];
  let seq = 0;
  const nextId = (prefix: string) => `${prefix}-${String(++seq).padStart(4, "0")}`;
  // A fixed clock: the ledger is asserted on ORDER, and a real clock would make two events
  // recorded in the same millisecond sort unpredictably.
  let tick = 0;
  const now = () => {
    tick += 1;
    return `2026-08-05T00:00:${String(tick).padStart(2, "0")}`;
  };

  const audit: { id: string; actor: string; action: string; resource_type: string; resource_id: string | null; outcome: string; data: Record<string, unknown>; created_at: string }[] = [];
  const record = (action: string, resourceId: string | null, actor = "operator") => {
    audit.push({
      id: nextId("evt"),
      actor,
      action,
      resource_type: "exercise",
      resource_id: resourceId,
      outcome: "success",
      data: {},
      created_at: now(),
    });
  };

  const templates = [
    {
      id: "tpl-0001",
      organization_id: ORG,
      name: "Web Breach 101",
      slug: "web-breach-101",
      display_name: "Web Breach 101",
      description: "Two-team web exploitation scenario.",
      created_at: "2026-08-01T00:00:00",
    },
  ];
  const versions = [
    {
      id: "ver-0001",
      template_id: "tpl-0001",
      version_number: 1,
      api_version: "secp.io/v1alpha2",
      content_hash: "sha256:bd8d77e726a6b413e0996aec114cb9651b066ceb773cc21e23e49679881bb5f0",
      spec: {},
      created_at: "2026-08-01T00:00:00",
      publication_provenance: null,
    },
    // A LOWER version number listed AFTER the highest, so a client that takes "the last element"
    // instead of the maximum picks the wrong one and the flow test notices.
    {
      id: "ver-0000",
      template_id: "tpl-0001",
      version_number: 0,
      api_version: "secp.io/v1alpha1",
      content_hash: "sha256:0000",
      spec: {},
      created_at: "2026-07-01T00:00:00",
      publication_provenance: null,
    },
  ];

  let exercise: FakeExercise | null = null;
  let plan: FakePlan | null = null;
  let instances: FakeInstance[] = [];

  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  const error = (status: number, code: string, message: string): Response =>
    json({ error: { code, message } }, status);

  // An unknown id must produce a 404 RESPONSE, never a thrown fetch. Throwing would surface to the
  // client as `api_unreachable` (a transport failure) and would let a genuine not-found bug hide
  // behind a network-shaped error.
  const findExercise = (id: string): FakeExercise | null =>
    exercise !== null && exercise.id === id ? exercise : null;

  const fakeFetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : String(input));
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(`${method} ${path}`);

    if (method === "GET" && path === "/api/v1/templates") return json(templates);
    if (method === "GET" && /^\/api\/v1\/templates\/[^/]+\/versions$/.test(path)) {
      return json(versions);
    }

    if (method === "POST" && path === "/api/v1/exercises") {
      const body = JSON.parse(String(init?.body ?? "{}")) as { name: string; version_id: string; template_id: string };
      exercise = {
        id: nextId("ex"),
        organization_id: ORG,
        template_id: body.template_id,
        environment_version_id: body.version_id,
        name: body.name,
        lifecycle_state: "draft",
        team_count: teamCount,
        created_at: now(),
      };
      record("exercise.created", exercise.id);
      return json(exercise, 201);
    }

    const exMatch = /^\/api\/v1\/exercises\/([^/]+)(\/.*)?$/.exec(path);
    if (exMatch !== null) {
      const tail = exMatch[2] ?? "";
      const ex = findExercise(exMatch[1]);
      if (ex === null) return error(404, "not_found", "exercise not found");

      if (method === "GET" && tail === "") return json(ex);

      if (method === "GET" && tail === "/plan") {
        return plan === null
          ? error(404, "not_found", "no plan has been generated")
          : json(plan);
      }

      if (method === "POST" && tail === "/validate") {
        ex.lifecycle_state = "validated";
        record("exercise.validated", ex.id);
        return json(ex);
      }

      if (method === "POST" && tail === "/plan") {
        plan = { id: nextId("plan"), exercise_id: ex.id, status: "generated" };
        ex.lifecycle_state = "planned";
        record("plan.generated", plan.id);
        return json(plan);
      }

      if (method === "POST" && tail === "/deploy") {
        // The gate is the server's: deploying without an approved plan is refused, and the flow
        // test relies on this being enforced here rather than only in the UI.
        if (plan === null || plan.status !== "approved") {
          return error(409, "approval_required", "an approved plan is required");
        }
        record("deploy.started", ex.id, "system");
        instances = Array.from({ length: teamCount }, (_, i) => ({
          id: nextId("inst"),
          exercise_id: ex.id,
          team_index: i + 1,
          team_ref: `team${i + 1}`,
          instance_ref: `${ex.name}-team${i + 1}`,
          lifecycle_state: "running",
          provider: "simulator",
        }));
        for (const inst of instances) record("instance.created", inst.id, "system");
        ex.lifecycle_state = "running";
        record("deploy.completed", ex.id, "system");
        return json({ id: nextId("run"), exercise_id: ex.id, kind: "deploy", status: "completed" });
      }

      if (method === "GET" && tail === "/instances") return json(instances);

      if (method === "GET" && tail === "/topology") {
        return json(
          instances.map((inst) => ({
            instance_id: inst.id,
            team_ref: inst.team_ref,
            team_index: inst.team_index,
            lifecycle_state: inst.lifecycle_state,
            nodes: [
              ...Array.from({ length: targetsPerTeam }, (_, n) => ({
                id: `${inst.id}-n${n}`,
                type: "host",
                data: {
                  label: `${inst.team_ref}-host${n}`,
                  kind: n === 0 ? "attacker" : "target",
                  role: n === 0 ? "attacker" : "web-server",
                  ip: `10.20.${inst.team_index}.${10 + n}`,
                  network: "team-network",
                },
              })),
              // A network node, which is NOT a target and must not be counted as one.
              {
                id: `${inst.id}-net`,
                type: "network",
                data: { label: "team-network", kind: "network", cidr: `10.20.${inst.team_index}.0/24` },
              },
            ],
            edges: [],
          })),
        );
      }

      const resetMatch = /^\/instances\/([^/]+)\/reset$/.exec(tail);
      if (method === "POST" && resetMatch !== null) {
        record("reset.started", resetMatch[1], "system");
        record("reset.completed", resetMatch[1], "system");
        return json({ id: nextId("run"), exercise_id: ex.id, kind: "reset", status: "completed" });
      }

      if (method === "POST" && tail === "/destroy") {
        record("destroy.started", ex.id, "system");
        for (const inst of instances) inst.lifecycle_state = "destroyed";
        ex.lifecycle_state = "destroyed";
        record("destroy.completed", ex.id, "system");
        return json({ id: nextId("run"), exercise_id: ex.id, kind: "destroy", status: "completed" });
      }
    }

    const planMatch = /^\/api\/v1\/plans\/([^/]+)\/(submit|approve|reject)$/.exec(path);
    if (method === "POST" && planMatch !== null) {
      if (plan === null || plan.id !== planMatch[1] || exercise === null) {
        return error(404, "not_found", "plan not found");
      }
      const ex = exercise;
      if (planMatch[2] === "submit") {
        plan.status = "awaiting_approval";
        ex.lifecycle_state = "awaiting_approval";
        record("plan.submitted", plan.id);
      } else if (planMatch[2] === "approve") {
        plan.status = "approved";
        ex.lifecycle_state = "approved";
        record("plan.approved", plan.id);
      } else {
        plan.status = "rejected";
        record("plan.rejected", plan.id);
      }
      return json(plan);
    }

    if (method === "GET" && path === "/api/v1/audit") {
      const forExercise = url.searchParams.get("exercise_id");
      // The real endpoint returns newest first; the client sorts. Returning them in the awkward
      // order here keeps the client's own ordering honest.
      const rows = [...audit].reverse();
      return json(forExercise === null ? rows : rows);
    }

    return error(404, "not_found", `fake control plane has no route for ${method} ${path}`);
  };

  return {
    fetch: fakeFetch,
    calls,
    auditActions: () => audit.map((e) => e.action),
    setState: (state: string) => {
      if (exercise === null) throw new Error("fake: no exercise created yet");
      exercise.lifecycle_state = state;
    },
  };
}
