"""Split an existing Authelia configuration into main + managed files (SPEC §3, §16.1).

    python -m scripts.split_config --config /config/configuration.yml --out /tmp/split

The input is never modified and the output directory must not exist. Moved
blocks are cut out of the original text verbatim (no YAML re-dump), so the
reduced main file keeps every other line unchanged (line endings are
normalised to LF). A structural merge check (and, unless --no-validate,
`authelia config validate` on both sets) proves nothing changed.

Nothing secret is printed: only key paths, counts and validator messages
(redacted).
"""

from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError
from ruamel.yaml.events import AliasEvent, NodeEvent

from app.authelia_cli import AutheliaCLI, AutheliaCLIError, ValidationResult, redact
from app.config_merge import merge_all

MAIN_NAME = "configuration.split.yml"
ACCESS_CONTROL_NAME = "access_control.yml"
OIDC_CLIENTS_NAME = "oidc_clients.yml"
DISABLED_RULES_NAME = "disabled_rules.yml"
LEFTOVERS_NAME = "migration_leftovers.yml"

# A commented-out rule starts with "- <rule key>:" (any order of keys).
_RULE_START = re.compile(
    r"^\s*-\s+(domain|domain_regex|policy|subject|resources|networks|methods|query)\s*:"
)


class SplitError(RuntimeError):
    """Migration cannot proceed; message is safe to print."""


# --------------------------------------------------------------------------- text helpers


def _is_blank(line: str) -> bool:
    return not line.strip()


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def _uncomment(line: str, *, eat_space: bool) -> str:
    """Remove the first '#' (and optionally one following space), keep the rest."""
    idx = line.index("#")
    rest = line[idx + 1 :]
    if eat_space and rest.startswith(" "):
        rest = rest[1:]
    return line[:idx] + rest


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _comment_content_col(line: str) -> int:
    """Column where a comment's text would sit if uncommented ('# Foo' at col 0 -> 0)."""
    return _indent(_uncomment(line, eat_space=True))


@dataclass(frozen=True)
class Span:
    start: int  # inclusive, 0-based line index
    end: int  # exclusive


def _block_span(lines: Sequence[str], key_line: int, boundary: int, key_col: int) -> Span:
    """Lines owned by the key at `key_line` whose block runs until `boundary`.

    Ownership of comments around the edges:
    - trailing blank lines go back to the following content;
    - a trailing run of comments directly above the next key (no blank line in
      between) whose text is not indented deeper than this key is prose for the
      next key, so it stays outside;
    - leading comments directly above the key (no blank line) with text not
      deeper than the key are prose for this key and come along.
    """
    end = boundary
    while end > key_line + 1 and _is_blank(lines[end - 1]):
        end -= 1
    if boundary < len(lines):
        probe = end
        while (
            probe > key_line + 1
            and _is_comment(lines[probe - 1])
            and _comment_content_col(lines[probe - 1]) <= key_col
        ):
            probe -= 1
        if probe < end and end == boundary:  # only when directly attached to the next key
            end = probe
            while end > key_line + 1 and _is_blank(lines[end - 1]):
                end -= 1
    start = key_line
    while (
        start > 0
        and _is_comment(lines[start - 1])
        and _comment_content_col(lines[start - 1]) <= key_col
    ):
        start -= 1
    return Span(start, end)


# --------------------------------------------------------------------------- yaml helpers


def _rt_yaml() -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    return yaml


def _safe_load(text: str) -> Any:
    return YAML(typ="safe", pure=True).load(text)


def _reject_anchors(text: str) -> None:
    try:
        for event in YAML(typ="rt").parse(io.StringIO(text)):
            if isinstance(event, AliasEvent) or (
                isinstance(event, NodeEvent) and getattr(event, "anchor", None)
            ):
                raise SplitError(
                    "YAML anchors/aliases found; they cannot span files, resolve them by hand first"
                )
    except YAMLError:
        raise SplitError("input is not valid YAML") from None


def _key_pos(node: CommentedMap, key: str) -> tuple[int, int]:
    line, col = node.lc.key(key)
    return int(line), int(col)


def _next_key_line(node: CommentedMap, key: str) -> int | None:
    keys = list(node.keys())
    idx = keys.index(key)
    for later in keys[idx + 1 :]:
        return _key_pos(node, later)[0]
    return None


def _boundary(path: Sequence[tuple[CommentedMap, str]], total_lines: int) -> int:
    """First line after the block of the innermost key in `path` (innermost last)."""
    for node, key in reversed(path):
        nxt = _next_key_line(node, key)
        if nxt is not None:
            return nxt
    return total_lines


# --------------------------------------------------------------------------- disabled rules


@dataclass
class DisabledRule:
    position: int
    rule: dict[str, Any]
    lines: list[int]


@dataclass
class Leftover:
    position: int
    text: str
    lines: list[int]


def _scan_commented_rules(
    lines: Sequence[str], region: Span, live_rule_lines: Sequence[int]
) -> tuple[list[DisabledRule], list[Leftover]]:
    disabled: list[DisabledRule] = []
    leftovers: list[Leftover] = []
    i = region.start
    while i < region.end:
        if not (_is_comment(lines[i]) and _RULE_START.match(_uncomment(lines[i], eat_space=False))):
            i += 1
            continue
        start = i
        hash_col = lines[i].index("#")
        dash_col = _indent(_uncomment(lines[i], eat_space=False))
        block = [start]
        i += 1
        while i < region.end and _is_comment(lines[i]):
            raw = _uncomment(lines[i], eat_space=False)
            # A rule commented out in one go has every '#' in the same column; a comment at
            # another column (e.g. "    # Notes" for the next live rule) is prose, not rule.
            if (
                lines[i].index("#") != hash_col
                or _RULE_START.match(raw)
                or (raw.strip() and _indent(raw) <= dash_col)
            ):
                break
            block.append(i)
            i += 1
        position = sum(1 for live in live_rule_lines if live < start)
        text = "\n".join(_uncomment(lines[n], eat_space=False)[dash_col:] for n in block)
        try:
            parsed = _safe_load(text)
        except YAMLError:
            parsed = None
        if (
            isinstance(parsed, list)
            and len(parsed) == 1
            and isinstance(parsed[0], dict)
            and "policy" in parsed[0]
            and ("domain" in parsed[0] or "domain_regex" in parsed[0])
        ):
            disabled.append(DisabledRule(position, parsed[0], block))
        else:
            leftovers.append(Leftover(position, "\n".join(lines[n] for n in block), block))
    return disabled, leftovers


# --------------------------------------------------------------------------- split


@dataclass
class SplitResult:
    main_text: str
    access_control_text: str
    oidc_clients_text: str | None
    disabled: list[DisabledRule] = field(default_factory=list)
    leftovers: list[Leftover] = field(default_factory=list)
    rule_count: int = 0
    client_count: int = 0

    @property
    def disabled_text(self) -> str | None:
        if not self.disabled:
            return None
        buf = io.StringIO()
        yaml = YAML(typ="rt")
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(
            {"disabled_rules": [{"position": d.position, "rule": d.rule} for d in self.disabled]},
            buf,
        )
        return "# Rules disabled in the configurator; never passed to Authelia.\n" + buf.getvalue()

    @property
    def leftovers_text(self) -> str | None:
        if not self.leftovers:
            return None
        out = [
            "# Commented-out blocks the migration could not parse. Review by hand.",
            "leftovers:",
        ]
        for item in self.leftovers:
            out.append(f"  - position: {item.position}")
            out.append("    text: |")
            out.extend(f"      {line}" for line in item.text.splitlines())
        return "\n".join(out) + "\n"


def split(text: str, *, import_disabled: bool = True) -> SplitResult:
    _reject_anchors(text)
    try:
        data = _rt_yaml().load(text)
    except YAMLError:
        raise SplitError("input is not valid YAML") from None
    if not isinstance(data, CommentedMap):
        raise SplitError("input is not a YAML mapping")
    if "access_control" not in data:
        raise SplitError("no top-level access_control section found")

    lines = text.splitlines()
    removed: set[int] = set()

    # access_control: the whole block moves.
    ac_line, ac_col = _key_pos(data, "access_control")
    ac_span = _block_span(lines, ac_line, _boundary([(data, "access_control")], len(lines)), ac_col)
    ac_lines = list(range(ac_span.start, ac_span.end))
    removed.update(ac_lines)

    access_control = data["access_control"]
    rules = access_control.get("rules") if isinstance(access_control, CommentedMap) else None
    disabled: list[DisabledRule] = []
    leftovers: list[Leftover] = []
    rule_count = 0
    if isinstance(rules, CommentedSeq):
        rule_count = len(rules)
        live_rule_lines = [int(rules.lc.item(i)[0]) for i in range(len(rules))]
        rules_key_line = _key_pos(access_control, "rules")[0]
        region = Span(rules_key_line + 1, ac_span.end)
        disabled, leftovers = _scan_commented_rules(lines, region, live_rule_lines)
    dropped: set[int] = set()
    if import_disabled:
        for rule in disabled:
            dropped.update(rule.lines)
        for block in leftovers:
            dropped.update(block.lines)
    else:
        disabled, leftovers = [], []
    ac_text = "\n".join(lines[n] for n in ac_lines if n not in dropped) + "\n"

    # identity_providers.oidc.clients: only the clients block moves.
    clients_text: str | None = None
    client_count = 0
    idp = data.get("identity_providers")
    oidc = idp.get("oidc") if isinstance(idp, CommentedMap) else None
    if isinstance(idp, CommentedMap) and isinstance(oidc, CommentedMap) and "clients" in oidc:
        path = [(data, "identity_providers"), (idp, "oidc"), (oidc, "clients")]
        cl_line, cl_col = _key_pos(oidc, "clients")
        cl_span = _block_span(lines, cl_line, _boundary(path, len(lines)), cl_col)
        cl_lines = range(cl_span.start, cl_span.end)
        removed.update(cl_lines)
        header = [
            f"{' ' * _key_pos(data, 'identity_providers')[1]}identity_providers:",
            f"{' ' * _key_pos(idp, 'oidc')[1]}oidc:",
        ]
        clients_text = "\n".join([*header, *(lines[n] for n in cl_lines)]) + "\n"
        clients = oidc["clients"]
        client_count = len(clients) if isinstance(clients, list) else 0
        if len(oidc) == 1:
            raise SplitError(
                "identity_providers.oidc contains only clients; the main file would be left "
                "with an empty oidc section. Move the whole identity_providers block by hand."
            )

    main_text = "\n".join(line for n, line in enumerate(lines) if n not in removed) + "\n"
    return SplitResult(
        main_text=main_text,
        access_control_text=ac_text,
        oidc_clients_text=clients_text,
        disabled=disabled,
        leftovers=leftovers,
        rule_count=rule_count,
        client_count=client_count,
    )


def check_structural_equality(original: str, result: SplitResult) -> None:
    """The koanf-style merge of the split files must equal the original data."""
    parts = [result.main_text, result.access_control_text]
    if result.oidc_clients_text:
        parts.append(result.oidc_clients_text)
    try:
        merged = merge_all([_safe_load(p) for p in parts])
        expected = _safe_load(original)
    except YAMLError:
        # Never surface the parser message: it can quote the offending (secret) line.
        raise SplitError("structural check failed: a split file is not valid YAML") from None
    if merged != expected:
        raise SplitError("structural check failed: merged split files differ from the original")
    main_data = _safe_load(result.main_text) or {}
    if "access_control" in main_data:
        raise SplitError("structural check failed: access_control still present in main file")
    oidc = (main_data.get("identity_providers") or {}).get("oidc") or {}
    if "clients" in oidc:
        raise SplitError("structural check failed: oidc clients still present in main file")


# --------------------------------------------------------------------------- cli


def _write_private(path: Path, content: str) -> None:
    """Create a file readable only by the owner from the first byte (it holds secrets)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)


def _write_outputs(out: Path, result: SplitResult) -> list[Path]:
    managed = out / "managed"
    out.mkdir(mode=0o700)
    managed.mkdir(mode=0o700)
    files = {
        out / MAIN_NAME: result.main_text,
        managed / ACCESS_CONTROL_NAME: result.access_control_text,
        managed / OIDC_CLIENTS_NAME: result.oidc_clients_text,
        managed / DISABLED_RULES_NAME: result.disabled_text,
        managed / LEFTOVERS_NAME: result.leftovers_text,
    }
    written = []
    for path, content in files.items():
        if content is not None:
            _write_private(path, content)
            written.append(path)
    return written


def _validator(mode: str) -> AutheliaCLI | None:
    if mode == "none":
        return None
    if mode == "local" or (mode == "auto" and shutil.which("authelia")):
        return AutheliaCLI.local()
    version = mode.removeprefix("docker:") if mode.startswith("docker:") else _dockerfile_version()
    return AutheliaCLI.via_docker(version)


def _dockerfile_version() -> str:
    dockerfile = Path(__file__).resolve().parent.parent / "Dockerfile"
    match = re.search(r"^ARG AUTHELIA_VERSION=(\S+)", dockerfile.read_text(), re.M)
    if not match:
        raise SplitError("cannot determine Authelia version; use --authelia docker:<version>")
    return match.group(1)


def _summary(label: str, result: ValidationResult) -> str:
    status = "ok" if result.ok else "FAILED"
    return f"{label}: {status}, {len(result.errors)} error(s), {len(result.warnings)} warning(s)"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--config", type=Path, required=True, help="existing main configuration")
    parser.add_argument("--out", type=Path, required=True, help="new output directory")
    parser.add_argument(
        "--no-import-disabled",
        action="store_true",
        help="leave commented-out rules in access_control.yml instead of importing them",
    )
    parser.add_argument(
        "--authelia",
        default="auto",
        help="validator: auto | local | docker:<version> | none (default: auto)",
    )
    parser.add_argument(
        "--managed-dir", default="/config/managed", help="CONFIG_MANAGED_DIR, for the hint"
    )
    args = parser.parse_args(argv)

    try:
        if args.out.exists():
            raise SplitError(f"output directory already exists: {args.out}")
        original = args.config.read_text()
        result = split(original, import_disabled=not args.no_import_disabled)
        check_structural_equality(original, result)
        print(f"access_control: {result.rule_count} live rule(s) -> managed/{ACCESS_CONTROL_NAME}")
        if result.oidc_clients_text:
            print(f"oidc clients: {result.client_count} -> managed/{OIDC_CLIENTS_NAME}")
        print(f"disabled rules imported: {len(result.disabled)}")
        if result.leftovers:
            print(f"UNPARSED commented blocks: {len(result.leftovers)} -> managed/{LEFTOVERS_NAME}")
        print("structural merge check: ok")

        # Write next to the target and only rename into place once everything checks out,
        # so a half-validated split never sits at the path the user was told to use.
        staging = args.out.with_name(args.out.name + ".partial")
        if staging.exists():
            raise SplitError(f"staging directory already exists: {staging}")
        written = _write_outputs(staging, result)

        validator = _validator(args.authelia)
        if validator is None:
            print("authelia validate: skipped (--authelia none)")
        else:
            print(f"validator: {' '.join(validator.argv_prefix)}")
            before = validator.validate([args.config])
            split_paths = [
                p for p in written if p.name in {MAIN_NAME, ACCESS_CONTROL_NAME, OIDC_CLIENTS_NAME}
            ]
            after = validator.validate(split_paths)
            print(_summary("authelia validate original", before))
            print(_summary("authelia validate split   ", after))
            for message in after.errors + after.warnings:
                print(f"  - {redact(message)}")
            problem = None
            if not after.ok:
                problem = "the split set does not validate"
            elif (before.ok, before.errors, before.warnings) != (
                after.ok,
                after.errors,
                after.warnings,
            ):
                problem = "validator results differ between original and split set"
            if problem:
                rejected = args.out.with_name(args.out.name + ".rejected")
                if rejected.exists():
                    rejected = staging  # never overwrite an earlier rejected run
                else:
                    staging.rename(rejected)
                raise SplitError(
                    f"{problem}; files kept for inspection only, DO NOT USE: {rejected}"
                )
        staging.rename(args.out)

        managed_files = [ACCESS_CONTROL_NAME] + (
            [OIDC_CLIENTS_NAME] if result.oidc_clients_text else []
        )
        hint = ",".join(
            [str(args.config.parent / "configuration.yml")]
            + [f"{args.managed_dir.rstrip('/')}/{name}" for name in managed_files]
        )
        print(f"\nReview {args.out}, then rename {MAIN_NAME} to configuration.yml and set:")
        print(f"  X_AUTHELIA_CONFIG={hint}")
        return 0
    except (SplitError, AutheliaCLIError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
