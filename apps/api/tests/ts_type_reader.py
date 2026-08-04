"""Read declarations out of a TypeScript declaration file as *text*.

Deliberately a text reader, not a transpiler and not an importer. The contract guard that uses this
compares the browser client's declared shapes against what the API actually serves, so the two
sides must be derived by genuinely independent routes. Anything that executed or type-checked
``types.ts`` against the backend would collapse that independence.

Scope is exactly what the guard needs and no more: ``export interface`` field names, and the string
members of an ``export type`` union. Types, optionality markers and nesting are parsed only well
enough to find field *names* at the top level of a declaration.

The reader is quote-aware throughout — comment stripping, brace matching and field splitting all
skip over string literals — so a ``//`` or a ``;`` inside a string member can never be mistaken for
syntax. Every accessor raises ``TypeScriptReadError`` when it finds nothing: a reader that silently
returns an empty set would make every comparison downstream pass by vacuity.
"""

from __future__ import annotations

import re
from pathlib import Path

_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_QUOTES = ("'", '"', "`")
_OPENERS = "{[("
_CLOSERS = "}])"


class TypeScriptReadError(RuntimeError):
    """The reader could not find what it was asked for.

    Raised rather than returning an empty result on purpose: absence-of-match and absence-of-input
    produce the same empty set but mean opposite things, and only one of them is a contract
    finding.
    """


def strip_comments(source: str) -> str:
    """Remove ``//`` and ``/* */`` comments, preserving string literals verbatim.

    Comments in ``types.ts`` carry prose that names fields ("no invitation id, no trust anchor"),
    so a guard that read them as declarations would find fields the client never declares.
    """
    out: list[str] = []
    index = 0
    end = len(source)
    while index < end:
        char = source[index]
        if char in _QUOTES:
            quote = char
            out.append(char)
            index += 1
            while index < end:
                if source[index] == "\\" and index + 1 < end:
                    out.append(source[index : index + 2])
                    index += 2
                    continue
                out.append(source[index])
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char == "/" and index + 1 < end and source[index + 1] == "/":
            while index < end and source[index] != "\n":
                index += 1
            continue
        if char == "/" and index + 1 < end and source[index + 1] == "*":
            index += 2
            while index + 1 < end and not (source[index] == "*" and source[index + 1] == "/"):
                index += 1
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _matching_brace(source: str, open_index: int) -> int:
    """Index of the ``}`` closing the ``{`` at ``open_index``, skipping strings."""
    depth = 0
    index = open_index
    end = len(source)
    while index < end:
        char = source[index]
        if char in _QUOTES:
            quote = char
            index += 1
            while index < end:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    break
                index += 1
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise TypeScriptReadError(f"unbalanced braces from offset {open_index}")


def interface_body(source: str, name: str) -> str:
    """The raw text between the braces of ``export interface <name>``.

    ``[^{]*`` after the name absorbs an ``extends`` clause, so an interface that inherits is found
    on the same footing as one that does not.
    """
    stripped = strip_comments(source)
    match = re.search(rf"export\s+interface\s+{re.escape(name)}\b[^{{]*\{{", stripped)
    if match is None:
        raise TypeScriptReadError(f"no `export interface {name}` in the source read")
    open_index = match.end() - 1
    close_index = _matching_brace(stripped, open_index)
    return stripped[open_index + 1 : close_index]


def _split_top_level(body: str) -> list[str]:
    """Split an interface body on its top-level ``;``/``,``, ignoring nesting and strings."""
    segments: list[str] = []
    current: list[str] = []
    depth = 0
    index = 0
    end = len(body)
    while index < end:
        char = body[index]
        if char in _QUOTES:
            quote = char
            current.append(char)
            index += 1
            while index < end:
                if body[index] == "\\" and index + 1 < end:
                    current.append(body[index : index + 2])
                    index += 2
                    continue
                current.append(body[index])
                if body[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            depth -= 1
        if depth == 0 and char in ";,":
            segments.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    segments.append("".join(current))
    return segments


def _field_name(segment: str) -> str | None:
    """The declared name of one ``name: type`` segment, or ``None`` if it declares no field."""
    head, separator, _ = segment.partition(":")
    if not separator:
        return None
    head = head.strip()
    if head.endswith("?"):
        head = head[:-1].strip()
    if not _IDENTIFIER.match(head):
        return None
    return head


def interface_fields(source: str, name: str) -> frozenset[str]:
    """Top-level field names declared by ``export interface <name>``.

    Optional (``field?:``) and required fields are returned alike: the guard compares *which* keys a
    body may carry, and a client that declares a key optional still declares it.
    """
    body = interface_body(source, name)
    fields = frozenset(
        found for segment in _split_top_level(body) if (found := _field_name(segment)) is not None
    )
    if not fields:
        raise TypeScriptReadError(f"`export interface {name}` parsed to zero fields")
    return fields


def interface_field_is_nullable(source: str, name: str, field: str) -> bool:
    """Whether ``<name>.<field>`` admits ``null`` in its declared type."""
    body = interface_body(source, name)
    for segment in _split_top_level(body):
        if _field_name(segment) != field:
            continue
        _, _, declared = segment.partition(":")
        return re.search(r"\bnull\b", declared) is not None
    raise TypeScriptReadError(f"`export interface {name}` declares no field `{field}`")


def type_union_members(source: str, name: str) -> tuple[str, ...]:
    """The quoted string members of ``export type <name> = "a" | "b" | ...``, in declared order."""
    stripped = strip_comments(source)
    match = re.search(rf"export\s+type\s+{re.escape(name)}\s*=", stripped)
    if match is None:
        raise TypeScriptReadError(f"no `export type {name}` in the source read")
    terminator = stripped.find(";", match.end())
    if terminator == -1:
        raise TypeScriptReadError(f"`export type {name}` has no terminating `;`")
    members = tuple(re.findall(r'"([^"]*)"', stripped[match.end() : terminator]))
    if not members:
        raise TypeScriptReadError(f"`export type {name}` parsed to zero string members")
    return members


def read_source(path: Path) -> str:
    """Read a declaration file, refusing an empty one.

    An unreadable or empty file would otherwise produce empty declarations, which compare as
    "nothing missing" against anything.
    """
    if not path.is_file():
        raise TypeScriptReadError(f"no such declaration file: {path}")
    source = path.read_text(encoding="utf-8")
    if not source.strip():
        raise TypeScriptReadError(f"declaration file is empty: {path}")
    return source
