"""The shipped range catalog.

Two starter ranges, deliberately, and they are the same content at two sizes rather than two
separate content projects:

``juice-shop-solo``  one intentionally vulnerable application, three challenges. The smallest thing
                     that still exercises the whole lifecycle — deploy, observed readiness,
                     deterministic reset, owned-resource teardown, residue proof.
``web-breach-lab``   that same target plus DVWA, six challenges. Adds the multi-component case:
                     two containers sharing one isolated network.

The Juice Shop component and its challenges are defined ONCE and shared, so the two templates
cannot drift to different images or different flags for the same target.

Scoring is NOT a container. The competition core is native and lives behind
:mod:`secp_api.services.competitions`, which is why no CTFd (or equivalent) image appears here. The
adapter boundary for an external scoring engine is the competition service itself — swapping it
would not touch the range lifecycle, the provider, or this catalog.

ABOUT THE FLAGS — READ THIS BEFORE TRUSTING THEM FOR A REAL EVENT
------------------------------------------------------------------
The flag values below are STATIC facts about these two pinned images: each one can only be obtained
by actually exploiting the deployed application, but none of them is secret from someone who knows
these applications well. They are correct for proving the mechanics (server-side scoring, no
duplicate credit, bounded attempts) and fine for a demo or a training lab. They are NOT sufficient
for a competitive event where participants may look things up.

Making them event-grade is a change to THIS FILE only, not to the schema or the API: flags are
already stored salted-hashed per competition (:class:`~secp_api.range_models.CompetitionFlag`), so
generating a per-range random value at seed time and planting it in the container is a catalog and
provider change with no migration and no contract change. That work is deliberately not done here.

The images are pinned to explicit version tags — never ``latest`` — and the digest actually
resolved at deploy time is recorded per resource, so what ran is evidenced rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secp_api.range_enums import ComponentRole


@dataclass(frozen=True)
class CatalogFlag:
    value: str
    label: str = ""
    case_sensitive: bool = False


@dataclass(frozen=True)
class CatalogChallenge:
    key: str
    title: str
    description: str
    category: str
    points: int
    component_key: str
    flags: tuple[CatalogFlag, ...]
    hint: str | None = None
    max_attempts: int = 25


@dataclass(frozen=True)
class CatalogComponent:
    key: str
    name: str
    role: ComponentRole
    image: str
    container_port: int | None = None
    protocol: str = "http"
    path: str = "/"
    env: dict[str, str] = field(default_factory=dict)
    readiness_timeout_seconds: int = 240


@dataclass(frozen=True)
class CatalogTemplate:
    slug: str
    name: str
    summary: str
    description: str
    provider: str
    difficulty: str
    estimated_deploy_seconds: int
    warning: str
    components: tuple[CatalogComponent, ...]
    challenges: tuple[CatalogChallenge, ...]

    @property
    def total_points(self) -> int:
        return sum(challenge.points for challenge in self.challenges)


#: OWASP Juice Shop, defined once and shared by every template that includes it, so the two
#: templates can never drift to different images or different flags for the same target.
JUICE_SHOP_COMPONENT = CatalogComponent(
    key="juice-shop",
    name="OWASP Juice Shop",
    role=ComponentRole.target,
    image="bkimminich/juice-shop:v17.1.0",
    container_port=3000,
    path="/",
    env={"NODE_ENV": "unsafe"},
    readiness_timeout_seconds=300,
)

JUICE_SHOP_CHALLENGES: tuple[CatalogChallenge, ...] = (
    CatalogChallenge(
        key="juice-hidden-scoreboard",
        title="Find Juice Shop's hidden scoreboard",
        description=(
            "Juice Shop hides its own challenge board behind an unlinked route. Find it and "
            "submit the route's path segment."
        ),
        category="discovery",
        points=50,
        component_key="juice-shop",
        hint="The client bundle knows every route the router can reach.",
        flags=(CatalogFlag(value="score-board", label="route segment"),),
    ),
    CatalogChallenge(
        key="juice-admin-sqli",
        title="Log in as the Juice Shop administrator",
        description=(
            "The login endpoint builds its query by string concatenation. Bypass it, then "
            "submit the email address of the account you land on."
        ),
        category="injection",
        points=150,
        component_key="juice-shop",
        hint="Terminate the string and comment out the rest of the query.",
        flags=(CatalogFlag(value="admin@juice-sh.op", label="admin email"),),
    ),
    CatalogChallenge(
        key="juice-exposed-file-server",
        title="Browse the exposed file server",
        description=(
            "A directory of internal documents is served without authentication. Find it and "
            "submit the filename of the acquisitions document."
        ),
        category="discovery",
        points=50,
        component_key="juice-shop",
        hint="Try the path a classic file-transfer service would use.",
        flags=(CatalogFlag(value="acquisitions.md", label="document filename"),),
    ),
)


#: DVWA, defined once and shared for the same reason :data:`JUICE_SHOP_COMPONENT` is: the Docker
#: lab and the Proxmox lab must stand up the same application at the same pinned version.
DVWA_COMPONENT = CatalogComponent(
    key="dvwa",
    name="DVWA",
    role=ComponentRole.target,
    image="vulnerables/web-dvwa:1.9",
    container_port=80,
    path="/",
    readiness_timeout_seconds=180,
)

DVWA_CHALLENGES: tuple[CatalogChallenge, ...] = (
    CatalogChallenge(
        key="dvwa-default-credentials",
        title="Get into DVWA",
        description=(
            "DVWA ships with a well-known administrative account. Log in, then submit the "
            "administrator's password as the flag."
        ),
        category="access",
        points=50,
        component_key="dvwa",
        hint="The application's own documentation gives this away.",
        flags=(CatalogFlag(value="password", label="admin password"),),
    ),
    CatalogChallenge(
        key="dvwa-sqli-password-hash",
        title="Extract a password hash by SQL injection",
        description=(
            "The SQL Injection page interpolates the User ID directly into a query. Use it to "
            "read the users table and submit the MD5 hash stored for the user 'gordonb'."
        ),
        category="injection",
        points=150,
        component_key="dvwa",
        hint="A user ID of 1' OR '1'='1 returns more rows than intended.",
        flags=(
            CatalogFlag(value="e99a18c428cb38d5f260853678922e03", label="gordonb password hash"),
        ),
    ),
    CatalogChallenge(
        key="dvwa-command-injection",
        title="Run a command on the DVWA host",
        description=(
            "The Command Injection page passes its input to a shell. Chain a command onto the "
            "ping and run 'id'. Submit the uid field exactly as the shell prints it."
        ),
        category="injection",
        points=150,
        component_key="dvwa",
        hint="A semicolon ends the ping and starts something else.",
        flags=(CatalogFlag(value="uid=33(www-data)", label="www-data uid"),),
    ),
)


#: A ONE-CONTAINER range. It exists because the smallest thing that exercises the entire lifecycle
#: end to end — create, pull, start, observe readiness by talking to the app, tear down, prove no
#: residue — is a single component, and a single component is what the first real-Docker proof runs
#: against. It is also the cheapest range to deploy on a laptop: no DVWA image, one port, one
#: readiness probe. ``web-breach-lab`` remains the fuller two-target lab.
JUICE_SHOP_SOLO = CatalogTemplate(
    slug="juice-shop-solo",
    name="Juice Shop (single target)",
    summary="One intentionally vulnerable web application on its own isolated Docker network.",
    description=(
        "A single-target range running OWASP Juice Shop, a modern single-page application with a "
        "REST API and a broad set of deliberately introduced flaws. It runs on a dedicated bridge "
        "network created for this range alone and is published on a loopback-only port on the "
        "host. Three challenges are seeded against it. Deploys in roughly a minute, which makes it "
        "the range to reach for when validating the lifecycle itself rather than running an event."
    ),
    provider="local_docker",
    difficulty="beginner",
    estimated_deploy_seconds=120,
    warning=(
        "Contains deliberately vulnerable software with known injection and access-control flaws. "
        "Ephemeral local Docker only. The published port binds to 127.0.0.1 and must never be "
        "forwarded, proxied, or exposed to an untrusted network."
    ),
    components=(JUICE_SHOP_COMPONENT,),
    challenges=JUICE_SHOP_CHALLENGES,
)


WEB_BREACH_LAB = CatalogTemplate(
    slug="web-breach-lab",
    name="Web Breach Lab",
    summary="Two intentionally vulnerable web applications on one isolated Docker network.",
    description=(
        "A self-contained web-application attack range. DVWA covers classic injection and access "
        "control; OWASP Juice Shop covers a modern single-page application with an API surface. "
        "Both run on a dedicated bridge network created for this range alone, and each is "
        "published on a loopback-only port on the host. Six challenges are seeded across the "
        "two targets."
    ),
    provider="local_docker",
    difficulty="beginner",
    estimated_deploy_seconds=240,
    warning=(
        "Contains deliberately vulnerable software with known remote-code-execution and injection "
        "flaws. Ephemeral local Docker only. Ports bind to 127.0.0.1 and must never be forwarded, "
        "proxied, or exposed to an untrusted network."
    ),
    components=(DVWA_COMPONENT, JUICE_SHOP_COMPONENT),
    challenges=(*DVWA_CHALLENGES, *JUICE_SHOP_CHALLENGES),
)


#: The same Web Breach Lab content on Proxmox instead of local Docker.
#:
#: The COMPONENTS AND CHALLENGES ARE THE SHARED OBJECTS, not copies: this template reuses
#: :data:`JUICE_SHOP_COMPONENT` and the DVWA component and challenge definitions that
#: ``web-breach-lab`` already uses. That is deliberate and load-bearing — the substrate changes, the
#: content must not. A Proxmox range and a Docker range of the same lab stand up the same
#: applications, at the same pinned versions, scored against the same flags.
#:
#: WHAT ``image`` MEANS ON A PROXMOX RANGE. On ``local_docker`` the component's ``image`` is pulled
#: directly. On Proxmox nothing pulls it: guests are cloned from a reviewed Proxmox TEMPLATE, named
#: by :class:`~secp_api.range_providers.proxmox_workload.ReviewedGuestImage`, which carries its own
#: ``template_ref``, ``image_digest`` and ``approval_reference``. The ``image`` recorded here is the
#: pinned application VERSION that reviewed template is required to contain, which is what keeps the
#: two substrates comparable and is checked by the ``workload_versions_pinned`` readiness
#: requirement. It is never a pull reference on this template.
#:
#: TWO TEAMS, and that is a floor rather than a default. The segregated network compiler refuses a
#: single-team request outright — with one team there is nothing to segregate, and cross-team
#: isolation is not a property that can be exercised, let alone proved. The attacker guest per team
#: is synthesised by the workload compiler and is deliberately NOT a catalog component: it is
#: competition infrastructure, not lab content.
PROXMOX_WEB_BREACH_LAB = CatalogTemplate(
    slug="proxmox-web-breach-lab",
    name="Web Breach Lab (Proxmox, two teams)",
    summary=(
        "The Web Breach Lab as full virtual machines on Proxmox, one segregated segment per team."
    ),
    description=(
        "The same two intentionally vulnerable web applications as 'web-breach-lab' — DVWA and "
        "OWASP Juice Shop — but stood up as full guests on a Proxmox cluster rather than as "
        "containers on one host. Each team gets its own SDN VNet, its own subnet and VLAN, its own "
        "copy of both targets and its own attacker workstation. Teams cannot reach each other, and "
        "no team segment can reach the Proxmox management plane; both are compiled into the "
        "firewall and proved against the compiled ruleset before anything is applied. A shared "
        "scoring segment is the one path every team is permitted, on the scoring port alone.\n\n"
        "This range is NOT applied by requesting a deploy. It compiles to a plan, the plan is "
        "approved by its exact hash, and apply is authorized separately — because on Proxmox a "
        "mistake creates real VMs on real hardware and consumes real addresses."
    ),
    provider="proxmox",
    difficulty="intermediate",
    estimated_deploy_seconds=1800,
    warning=(
        "Contains deliberately vulnerable software with known remote-code-execution and injection "
        "flaws, running as full virtual machines on shared cluster hardware. Every team segment is "
        "compiled to be unable to reach the Proxmox management plane, the control plane, or "
        "another team — that isolation is proved against the compiled firewall before apply and "
        "observed again after it. Do not apply this range to a cluster whose management network "
        "you have not declared, and do not attach a team segment to a bridge that carries "
        "management traffic."
    ),
    components=(
        DVWA_COMPONENT,
        JUICE_SHOP_COMPONENT,
    ),
    challenges=(*DVWA_CHALLENGES, *JUICE_SHOP_CHALLENGES),
)


CATALOG: tuple[CatalogTemplate, ...] = (JUICE_SHOP_SOLO, WEB_BREACH_LAB, PROXMOX_WEB_BREACH_LAB)


def get_template(slug: str) -> CatalogTemplate | None:
    return next((template for template in CATALOG if template.slug == slug), None)


def template_spec_document(template: CatalogTemplate) -> dict:
    """The frozen definition persisted on ``RangeTemplate.spec``.

    Flag VALUES are deliberately absent — the persisted spec is readable by anything that can read
    the templates table, and a stored plaintext flag there would defeat the hashing done on
    :class:`~secp_api.range_models.CompetitionFlag`. Only the flag COUNT is recorded.
    """
    return {
        "components": [
            {
                "key": component.key,
                "name": component.name,
                "role": component.role.value,
                "image": component.image,
                "container_port": component.container_port,
                "protocol": component.protocol,
                "path": component.path,
                "env": dict(component.env),
                "readiness_timeout_seconds": component.readiness_timeout_seconds,
            }
            for component in template.components
        ],
        "challenges": [
            {
                "key": challenge.key,
                "title": challenge.title,
                "description": challenge.description,
                "category": challenge.category,
                "points": challenge.points,
                "component_key": challenge.component_key,
                "hint": challenge.hint,
                "max_attempts": challenge.max_attempts,
                "flag_count": len(challenge.flags),
            }
            for challenge in template.challenges
        ],
    }
