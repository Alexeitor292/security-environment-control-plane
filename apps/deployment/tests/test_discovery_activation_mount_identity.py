"""POSIX filesystem-identity tests for PR5F host mount isolation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from secp_discovery_activation.adapters import ActivationAdapterError
from secp_discovery_activation.local_adapter import PosixMountSourceIdentityResolver

_POSIX_IDENTITY_PRIMITIVES = bool(
    os.name == "posix"
    and getattr(os, "O_PATH", 0)
    and getattr(os, "O_NOFOLLOW", 0)
    and os.open in getattr(os, "supports_dir_fd", set())
)

pytestmark = pytest.mark.skipif(
    not _POSIX_IDENTITY_PRIMITIVES,
    reason="secure POSIX dir-fd/O_PATH/O_NOFOLLOW traversal is unavailable",
)


def _overlap(source: Path, protected: Path) -> bool:
    result = PosixMountSourceIdentityResolver().classify(
        source_paths=(str(source),),
        protected_paths=(str(protected),),
    )
    return result[0].overlaps[0]


def test_identity_resolver_detects_exact_hardlink_and_both_ancestry_directions(
    tmp_path: Path,
) -> None:
    protected_directory = tmp_path / "protected"
    protected_directory.mkdir()
    protected_file = protected_directory / "secret"
    protected_file.write_bytes(b"secret")
    hardlink = tmp_path / "opaque-hardlink"
    os.link(protected_file, hardlink)
    descendant = protected_directory / "nested"
    descendant.mkdir()
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"safe")

    assert _overlap(protected_file, protected_file)
    assert _overlap(hardlink, protected_file)
    assert _overlap(protected_directory, protected_file)
    assert _overlap(descendant, protected_directory)
    assert not _overlap(unrelated, protected_file)


def test_identity_resolver_refuses_source_and_intermediate_symlinks(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    secret = real_directory / "secret"
    secret.write_bytes(b"secret")
    direct_link = tmp_path / "direct-link"
    direct_link.symlink_to(secret)
    directory_link = tmp_path / "directory-link"
    directory_link.symlink_to(real_directory, target_is_directory=True)
    resolver = PosixMountSourceIdentityResolver()

    for unsafe_source in (direct_link, directory_link / "secret"):
        with pytest.raises(ActivationAdapterError) as caught:
            resolver.classify(
                source_paths=(str(unsafe_source),),
                protected_paths=(str(secret),),
            )
        assert caught.value.reason_code == "mount_source_identity_symlink_refused"

    with pytest.raises(ActivationAdapterError) as caught:
        resolver.classify(
            source_paths=(str(secret),),
            protected_paths=(str(direct_link),),
        )
    assert caught.value.reason_code == "mount_source_identity_symlink_refused"


def test_identity_resolver_requires_every_mounted_source_to_exist(tmp_path: Path) -> None:
    existing = tmp_path / "existing"
    existing.write_bytes(b"source")
    protected = tmp_path / "protected"
    protected.write_bytes(b"secret")

    with pytest.raises(ActivationAdapterError) as caught:
        PosixMountSourceIdentityResolver().classify(
            source_paths=(str(existing), str(tmp_path / "missing-source")),
            protected_paths=(str(protected),),
        )

    assert caught.value.reason_code == "mount_source_identity_unresolvable"


def test_incomplete_protected_suffix_allows_ancestor_but_not_sibling_false_positive(
    tmp_path: Path,
) -> None:
    sibling_directory = tmp_path / "sibling"
    sibling_directory.mkdir()
    sibling = sibling_directory / "source"
    sibling.write_bytes(b"safe")
    future_protected = tmp_path / "not-created" / "nested" / "secret"
    resolver = PosixMountSourceIdentityResolver()

    result = resolver.classify(
        source_paths=(str(tmp_path), str(sibling)),
        protected_paths=(str(future_protected),),
    )

    assert result[0].overlaps == (True,)
    assert result[1].overlaps == (False,)


def test_identity_bindings_change_when_a_protected_object_is_replaced(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"source")
    protected = tmp_path / "protected"
    protected.write_bytes(b"first")
    resolver = PosixMountSourceIdentityResolver()
    first = resolver.classify(
        source_paths=(str(source),),
        protected_paths=(str(protected),),
    )

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"second")
    os.replace(replacement, protected)
    second = resolver.classify(
        source_paths=(str(source),),
        protected_paths=(str(protected),),
    )

    assert first != second
    assert first[0].protected_bindings != second[0].protected_bindings
