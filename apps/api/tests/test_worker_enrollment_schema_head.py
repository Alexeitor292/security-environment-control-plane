"""Sole-head proof + PR5H live-schema readiness (SECP-PR5H-A, ADR-027).

Two separate properties, deliberately kept apart:

1. the repository has EXACTLY ONE Alembic head, and it is the new PR5H head chained from PR5F;
2. PR5H enrollment operations require the LIVE database to be at that head — an older (legacy) live
   schema, an unknown head, a branched ``alembic_version`` or an unreadable version table all refuse
   closed, no matter what a signed artifact says.
"""

from __future__ import annotations

import glob
import os
import re

import pytest
from secp_api.worker_enrollment_schema import (
    RUNTIME_REQUIRED_MIGRATION_HEAD,
    EnrollmentSchemaError,
    assert_enrollment_schema_ready,
    enrollment_schema_ready,
    observed_migration_head,
)
from sqlalchemy import text

_VERSIONS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations", "versions")


def _revision_graph() -> tuple[dict[str, str], set[str]]:
    revisions: dict[str, str] = {}
    downs: set[str] = set()
    for path in glob.glob(os.path.join(_VERSIONS, "*.py")):
        source = open(path, encoding="utf-8").read()
        rev = re.search(r'^revision(?::[^=]*)?\s*=\s*["\']([^"\']+)', source, re.M)
        down = re.search(r'^down_revision(?::[^=]*)?\s*=\s*["\']([^"\']+)', source, re.M)
        if rev:
            revisions[rev.group(1)] = os.path.basename(path)
        if down:
            downs.add(down.group(1))
    return revisions, downs


def test_repository_has_exactly_one_alembic_head_and_it_is_pr5h() -> None:
    revisions, downs = _revision_graph()
    heads = sorted(rev for rev in revisions if rev not in downs)
    assert heads == [RUNTIME_REQUIRED_MIGRATION_HEAD], heads


def test_pr5h_head_chains_directly_from_the_pr5f_head() -> None:
    revisions, _ = _revision_graph()
    assert RUNTIME_REQUIRED_MIGRATION_HEAD in revisions
    source = open(os.path.join(_VERSIONS, revisions[RUNTIME_REQUIRED_MIGRATION_HEAD])).read()
    assert re.search(r'^down_revision[^=]*=\s*"d8f1a2b3c4e5"', source, re.M)


def test_the_four_enrollment_tables_are_registered_on_the_shared_metadata() -> None:
    from secp_api.models import Base

    expected = {
        "worker_enrollment_invitation",
        "worker_enrollment_state",
        "worker_enrollment_revision",
        "worker_enrollment_step_receipt",
    }
    assert expected <= set(Base.metadata.tables)


# --- live-schema readiness (independent of any signed artifact) --------------------------------


def _set_head(session, value: str | None, *, rows: int = 1) -> None:
    session.execute(text("DELETE FROM alembic_version"))
    if value is not None:
        for _ in range(rows):
            session.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": value}
            )
    session.flush()


@pytest.fixture
def version_table(session):  # noqa: ANN001, ANN201
    session.execute(
        text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL)")
    )
    session.flush()
    return session


def test_live_schema_at_the_required_head_is_ready(version_table) -> None:  # noqa: ANN001
    _set_head(version_table, RUNTIME_REQUIRED_MIGRATION_HEAD)
    assert observed_migration_head(version_table) == RUNTIME_REQUIRED_MIGRATION_HEAD
    assert enrollment_schema_ready(version_table) is True
    assert_enrollment_schema_ready(version_table)  # does not raise


def test_legacy_live_schema_refuses_pr5h_operations(version_table) -> None:  # noqa: ANN001
    # accepting an already-issued legacy-head SIGNED offer must never imply the new schema exists
    _set_head(version_table, "d8f1a2b3c4e5")
    assert enrollment_schema_ready(version_table) is False
    with pytest.raises(EnrollmentSchemaError) as exc:
        assert_enrollment_schema_ready(version_table)
    assert exc.value.reason_code == "enrollment_schema_head_unavailable"


@pytest.mark.parametrize("head", ["c4e2f9a1b7d3", "000000000000", "b6e2f4a9c1d8"])
def test_unknown_older_and_future_live_heads_refuse(version_table, head: str) -> None:  # noqa: ANN001
    _set_head(version_table, head)
    assert enrollment_schema_ready(version_table) is False


def test_branched_version_table_refuses_closed(version_table) -> None:  # noqa: ANN001
    # an ambiguous multi-row alembic_version is NOT silently resolved to the first row
    _set_head(version_table, RUNTIME_REQUIRED_MIGRATION_HEAD, rows=2)
    assert observed_migration_head(version_table) is None
    assert enrollment_schema_ready(version_table) is False


def test_absent_version_row_refuses_closed(version_table) -> None:  # noqa: ANN001
    _set_head(version_table, None)
    assert observed_migration_head(version_table) is None
    assert enrollment_schema_ready(version_table) is False
