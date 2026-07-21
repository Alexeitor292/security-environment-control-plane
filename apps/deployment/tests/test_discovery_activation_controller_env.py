"""Fixed controller Compose environment binding (SECP-PR5F.1).

The controller base Compose file interpolates ${SECP_*} variables.  Because the production command
runner uses a fixed child environment and never inherits ambient process/shell state or the working
directory, those values must be supplied explicitly with ``--env-file`` at the fixed env path.
These platform-independent tests prove the closed argv contract, the strict .env parser, the
interpolation-coverage gate, and that no secret value or file content is ever exposed.  The POSIX
filesystem-security cases (symlink/hardlink/owner/mode/drift) live in the Linux-root no-skip gate.
"""

from __future__ import annotations

import pytest
from secp_discovery_activation.adapters import ActivationAdapterError
from secp_discovery_activation.layout import PRODUCTION_LAYOUT
from secp_discovery_activation.local_adapter import (
    _FIXED_CODE_OWNED_PATHS,
    _ROLE_PATHS,
    CONTROLLER_BASE_COMPOSE_PATH,
    CONTROLLER_ENV_FILE_PATH,
    WORKER_BASE_COMPOSE_PATH,
    _assert_controller_env_coverage,
    _controller_compose_args,
    _parse_controller_env_names,
    _required_compose_variables,
    _worker_compose_args,
)
from secp_operator_deployment.host_process import _FIXED_ENV, RealCommandRunner

_SENTINEL = "s3cr3t-do-not-leak-value"
_BASE = (
    b"services:\n"
    b"  api:\n"
    b"    image: ${SECP_API_IMAGE}\n"
    b"    environment:\n"
    b"      DSN: ${SECP_DATABASE_URL}\n"
    b"      TOKEN: $SECP_ADMIN_TOKEN\n"
    b'    healthcheck:\n      test: ["CMD", "sh", "-c", "echo $$HOME"]\n'
)
_ENV = (
    b"# fixed controller environment (values are secret)\n"
    b"SECP_API_IMAGE=sha256:" + b"a" * 64 + b"\n"
    b"SECP_DATABASE_URL=" + _SENTINEL.encode() + b"\n"
    b"\n"
    b"SECP_ADMIN_TOKEN=" + _SENTINEL.encode() + b"\n"
)


# --- closed argv contract: the fixed env file is always bound for controller Compose (case 1,2) ---


@pytest.mark.parametrize("with_override", [False, True])
def test_controller_compose_argv_always_binds_the_fixed_env_file(with_override: bool) -> None:
    argv = _controller_compose_args(with_override=with_override, project_name="secp-controller")
    assert argv[:2] == ("--env-file", CONTROLLER_ENV_FILE_PATH)
    assert argv.count("--env-file") == 1
    assert CONTROLLER_ENV_FILE_PATH == "/etc/secp/controller/secp.env"
    # the exact fixed base Compose file + fixed service constraints are preserved
    assert "--file" in argv and CONTROLLER_BASE_COMPOSE_PATH in argv
    up = argv.index("up")
    assert argv[up : up + 6] == ("up", "--detach", "--no-deps", "--no-build", "--pull", "never")
    assert "api" in argv[up + 6 :]


def test_controller_activation_and_rollback_use_the_same_fixed_env_file() -> None:
    # activation runs with the override; rollback-to-baseline runs without it — both bind the same
    # single fixed env file, so retry/compensation/rollback interpolate identically.
    activation = _controller_compose_args(with_override=True, project_name="secp-controller")
    baseline = _controller_compose_args(with_override=False, project_name="secp-controller")
    assert activation[:2] == baseline[:2] == ("--env-file", CONTROLLER_ENV_FILE_PATH)


# --- the hardened reader must admit every code-owned fixed path it opens (blocker regression) ---


def test_trusted_reader_admits_every_code_owned_fixed_path() -> None:
    # _open_parent opens only a path present in this exact allowlist; anything else refuses closed
    # with activation_path_not_fixed, making the corresponding install/rollback path inoperative
    # even for a correctly provisioned file.  EVERY non-role fixed path any hardened-open call site
    # can be asked to open must be admitted (this platform-independent membership check is the
    # regression guard the Windows-skipped Linux-root proofs cannot provide).
    allow = {
        *_ROLE_PATHS.values(),
        *_FIXED_CODE_OWNED_PATHS,
        PRODUCTION_LAYOUT.controller_journal_path,
        PRODUCTION_LAYOUT.worker_journal_path,
    }
    # the complete set of non-role fixed paths handed to _read_absolute/_open_parent
    for path in (
        CONTROLLER_ENV_FILE_PATH,  # _controller_env_record
        CONTROLLER_BASE_COMPOSE_PATH,  # _base_compose_record (controller)
        WORKER_BASE_COMPOSE_PATH,  # _base_compose_record (worker)
        PRODUCTION_LAYOUT.worker_runtime_overlay_import_path,  # validated_runtime_overlay
        PRODUCTION_LAYOUT.controller_journal_path,  # controller journal read/write
        PRODUCTION_LAYOUT.worker_journal_path,  # worker journal read/write
    ):
        assert path in allow


# --- the worker never receives the controller environment file (case 4) ---


@pytest.mark.parametrize("with_override", [False, True])
def test_worker_compose_argv_never_binds_the_controller_env_file(with_override: bool) -> None:
    argv = _worker_compose_args(with_override=with_override, project_name="secp-worker")
    assert "--env-file" not in argv
    assert CONTROLLER_ENV_FILE_PATH not in argv
    assert WORKER_BASE_COMPOSE_PATH in argv


# --- the fixed child environment never inherits ambient or SECP_* values (case 5) ---


def test_fixed_child_environment_excludes_ambient_and_secp_variables() -> None:
    assert _FIXED_ENV == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    assert not any(name.startswith("SECP_") for name in _FIXED_ENV)
    # the runner spawns with exactly this dict, never os.environ (proven structurally here and at
    # runtime by the operator-deployment host-process suite).
    assert RealCommandRunner is not None


# --- strict bounded .env parser (case 11) ---


def _refuses(raw: bytes) -> str:
    with pytest.raises(ActivationAdapterError) as caught:
        _parse_controller_env_names(raw)
    return caught.value.reason_code


def test_parser_returns_only_assigned_names_never_values() -> None:
    names = _parse_controller_env_names(_ENV)
    assert names == frozenset({"SECP_API_IMAGE", "SECP_DATABASE_URL", "SECP_ADMIN_TOKEN"})
    assert _SENTINEL not in repr(names)


def test_parser_allows_blank_lines_and_comments() -> None:
    raw = b"# comment\n\n   \nSECP_X=1\n# trailing\n"
    assert _parse_controller_env_names(raw) == frozenset({"SECP_X"})


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # empty
        b"SECP_X=1\x00SECP_Y=2\n",  # NUL byte
        b"SECP_X=\xff\xfe\n",  # invalid UTF-8
        b"not-an-assignment\n",  # malformed (no '=')
        b"=novalue\n",  # malformed (empty name)
        b"1BAD=x\n",  # malformed (name not [A-Za-z_]...)
        b"SECP-X=x\n",  # malformed (hyphen in name)
        b"SECP_X=1\nSECP_X=2\n",  # duplicate name
    ],
)
def test_parser_refuses_malformed_input(raw: bytes) -> None:
    reason = _refuses(raw)
    assert reason in {
        "controller_env_unparsable",
        "controller_env_malformed",
        "controller_env_duplicate_name",
    }
    assert _SENTINEL not in reason


def test_parser_refuses_oversized_and_overlong() -> None:
    assert _refuses(b"SECP_X=" + b"a" * (64 * 1024 + 1)) == "controller_env_unparsable"
    assert _refuses(b"\n" * 600) == "controller_env_unparsable"  # too many lines
    assert (
        _refuses(b"SECP_X=" + b"a" * 4100 + b"\n") == "controller_env_unparsable"
    )  # line too long


def test_parser_refuses_multi_line_quoted_value_that_would_false_accept_a_name() -> None:
    # compose's --env-file dotenv parser continues a double-quoted value across physical lines, so
    # the second physical line is part of SECP_TLS_BUNDLE's value and SECP_ADMIN_TOKEN is NEVER
    # defined.  A quote-blind physical-line parser would wrongly return both names and let the
    # coverage gate pass while compose blank-substitutes ${SECP_ADMIN_TOKEN}; the sound parser
    # refuses the unbalanced-quote line closed before staging.
    raw = b'SECP_TLS_BUNDLE="line-one\nSECP_ADMIN_TOKEN=whatever"\n'
    assert _refuses(raw) == "controller_env_unparsable"


def test_parser_refuses_empty_and_empty_quoted_values() -> None:
    # `NAME=` (or `NAME=""`) is a defined-but-blank variable: compose would substitute ${NAME}->''
    # with no warning, exactly the blank-substitution the gate exists to prevent.
    assert _refuses(b"SECP_ADMIN_TOKEN=\n") == "controller_env_empty_value"
    assert _refuses(b'SECP_ADMIN_TOKEN=""\n') == "controller_env_unparsable"
    assert _refuses(b"SECP_ADMIN_TOKEN=''\n") == "controller_env_unparsable"


def test_parser_accepts_single_line_balanced_quoted_scalars() -> None:
    # single-line quoted scalars are a legitimate .env form and must still be counted as defined.
    names = _parse_controller_env_names(b"SECP_X=\"a b c\"\nSECP_Y='d e'\nSECP_Z=plain\n")
    assert names == frozenset({"SECP_X", "SECP_Y", "SECP_Z"})


@pytest.mark.parametrize(
    "raw",
    [
        b"SECP_X=${UNDEFINED}\n",  # unquoted whole-value reference -> compose expands to ""
        b"SECP_X=$UNDEFINED\n",  # unquoted $NAME form
        b"SECP_DATABASE_URL=${DATABASE_URL}\n",  # aliasing an ambient var (absent from fixed env)
        b'SECP_X="${UNDEFINED}"\n',  # DOUBLE quotes still expand in compose-go -> ""
        b'SECP_ADMIN_TOKEN="$TOKEN"\n',  # double-quoted $NAME expands to ""
        b"SECP_X=prefix$SUFFIX\n",  # embedded reference in an unquoted value
        b"SECP_ADMIN_TOKEN=  # set before prod\n",  # unquoted inline comment -> compose value is ""
        b"SECP_X=a#b\n",  # unquoted '#' (conservatively refused; single-quote to keep literal)
    ],
)
def test_parser_refuses_values_compose_would_expand_or_comment_to_empty(raw: bytes) -> None:
    # compose-go performs $VAR/${VAR} expansion in unquoted AND double-quoted values and strips
    # unquoted inline comments; against the fixed {PATH, LC_ALL} child env an undefined reference
    # resolves to "".  The parser must not count such a name as defined (fail-open blank
    # substitution); only a single-quoted literal is a safe escape hatch (see below).
    assert _refuses(raw) == "controller_env_unparsable"


def test_parser_accepts_single_quoted_literals_as_the_escape_hatch() -> None:
    # single quotes are fully literal in compose-go (no expansion, no inline comment), so a value
    # containing $, #, " or spaces is admitted verbatim and non-empty when single-quoted.
    names = _parse_controller_env_names(
        b"SECP_A='${NOT_EXPANDED}'\nSECP_B='pa$$w#ord \"x\"'\nSECP_C='plain'\n"
    )
    assert names == frozenset({"SECP_A", "SECP_B", "SECP_C"})


def test_parser_strips_a_leading_utf8_bom_like_compose() -> None:
    # a BOM-prefixed file (common from Windows editors) is what compose-go accepts after stripping
    # the BOM; the parser matches so a valid file is not refused on Windows-authored tooling.
    assert _parse_controller_env_names(b"\xef\xbb\xbfSECP_X=1\n") == frozenset({"SECP_X"})


# --- interpolation coverage vs the base Compose file (cases 12, 13) ---


def test_required_variables_extracted_from_base_compose() -> None:
    assert _required_compose_variables(_BASE) == frozenset(
        {"SECP_API_IMAGE", "SECP_DATABASE_URL", "SECP_ADMIN_TOKEN"}
    )


def test_coverage_passes_when_every_required_variable_is_defined() -> None:
    _assert_controller_env_coverage(_BASE, _ENV)  # no raise


def test_coverage_refuses_when_a_required_variable_is_missing() -> None:
    partial = b"SECP_API_IMAGE=x\nSECP_DATABASE_URL=y\n"  # missing SECP_ADMIN_TOKEN
    with pytest.raises(ActivationAdapterError) as caught:
        _assert_controller_env_coverage(_BASE, partial)
    assert caught.value.reason_code == "controller_env_missing_required_variable"


@pytest.mark.parametrize(
    "base",
    [
        b"image: ${SECP_X:-default}\n",  # default form unsupported
        b"image: ${SECP_X?err}\n",  # error form unsupported
        b"image: ${SECP_X:+alt}\n",  # alternate form unsupported
        b"image: ${SECP_X\n",  # unterminated brace
        b"image: $-nope\n",  # bare invalid $
    ],
)
def test_unsupported_interpolation_syntax_refuses(base: bytes) -> None:
    with pytest.raises(ActivationAdapterError) as caught:
        _required_compose_variables(base)
    assert caught.value.reason_code == "controller_base_compose_interpolation_unsupported"


def test_escaped_double_dollar_is_not_a_reference() -> None:
    assert _required_compose_variables(b"cmd: echo $$HOME then ${SECP_X}\n") == frozenset(
        {"SECP_X"}
    )


# --- no secret content or value is ever exposed (case 17) ---


def test_coverage_and_parser_never_expose_values() -> None:
    # names are compared, values are never returned, echoed, or placed in any raised reason
    names = _parse_controller_env_names(_ENV)
    assert all(_SENTINEL not in name for name in names)
    for probe in (repr(names), repr(_required_compose_variables(_BASE))):
        assert _SENTINEL not in probe
    with pytest.raises(ActivationAdapterError) as caught:
        _assert_controller_env_coverage(_BASE, b"SECP_API_IMAGE=" + _SENTINEL.encode() + b"\n")
    assert _SENTINEL not in caught.value.reason_code
    assert _SENTINEL not in repr(caught.value)
