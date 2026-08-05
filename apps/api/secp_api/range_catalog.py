"""The shipped range catalog.

Exactly ONE complete starter range, deliberately: two intentionally vulnerable web applications on
a dedicated isolated network, six seeded challenges, and bounded flags. It is the smallest
combination that exercises every part of the lifecycle (multi-component deploy, observed readiness,
deterministic reset, owned-resource teardown) without turning the first delivery into a content
project.

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
    components=(
        CatalogComponent(
            key="dvwa",
            name="DVWA",
            role=ComponentRole.target,
            image="vulnerables/web-dvwa:1.9",
            container_port=80,
            path="/",
            readiness_timeout_seconds=180,
        ),
        CatalogComponent(
            key="juice-shop",
            name="OWASP Juice Shop",
            role=ComponentRole.target,
            image="bkimminich/juice-shop:v17.1.0",
            container_port=3000,
            path="/",
            env={"NODE_ENV": "unsafe"},
            readiness_timeout_seconds=300,
        ),
    ),
    challenges=(
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
                CatalogFlag(
                    value="e99a18c428cb38d5f260853678922e03", label="gordonb password hash"
                ),
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
    ),
)


CATALOG: tuple[CatalogTemplate, ...] = (WEB_BREACH_LAB,)


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
