"""Planted misconfigurations (policy/misconfigs.yml), documented exceptions and run settings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TOOLS = ("prowler", "postureck")


class ConfigError(ValueError):
    """A policy file is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Detector:
    tool: str
    check_id: str


@dataclass(frozen=True)
class Planted:
    id: str
    title: str
    cis: str
    resource_match: str
    detectors: tuple[Detector, ...]


@dataclass(frozen=True)
class Exception_:  # noqa: N801 - "Exception" is a builtin
    check_id: str
    resource_match: str
    reason: str
    owner_role: str


@dataclass(frozen=True)
class Settings:
    framework: str
    services: tuple[str, ...]
    prowler_version: str
    localstack_image: str


def _read(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc


def _text(entry: dict[str, Any], key: str, where: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: '{key}' is missing or empty")
    return value


def _list(data: Any, key: str, path: Path) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise ConfigError(f"{path}: expected a '{key}' list")
    items: list[dict[str, Any]] = data[key]
    if not all(isinstance(i, dict) for i in items):
        raise ConfigError(f"{path}: every '{key}' entry must be a mapping")
    return items


def load_planted(path: Path) -> tuple[Planted, ...]:
    out: list[Planted] = []
    for entry in _list(_read(path), "planted", path):
        pid = _text(entry, "id", f"{path} planted item")
        where = f"{path} {pid}"
        raw = entry.get("detectors")
        if not isinstance(raw, list) or not raw:
            raise ConfigError(f"{where}: needs at least one detector")
        detectors = []
        for d in raw:
            tool = _text(d, "tool", where) if isinstance(d, dict) else ""
            if tool not in TOOLS:
                raise ConfigError(f"{where}: unknown detector tool {tool!r}")
            detectors.append(Detector(tool, _text(d, "check_id", where)))
        item = Planted(
            pid,
            _text(entry, "title", where),
            str(entry.get("cis", "")).strip() or _text(entry, "cis", where),
            _text(entry, "resource_match", where),
            tuple(detectors),
        )
        if any(p.id == item.id for p in out):
            raise ConfigError(f"{path}: duplicate planted id {pid}")
        out.append(item)
    if not out:
        raise ConfigError(f"{path}: no planted misconfiguration")
    return tuple(out)


def load_exceptions(path: Path) -> tuple[Exception_, ...]:
    out = []
    for entry in _list(_read(path), "exceptions", path):
        check = _text(entry, "check_id", f"{path} exception")
        where = f"{path} exception {check}"
        out.append(
            Exception_(
                check,
                _text(entry, "resource_match", where),
                _text(entry, "reason", where),
                _text(entry, "owner_role", where),
            )
        )
    return tuple(out)


def load_settings(path: Path) -> Settings:
    data = _read(path)
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping")
    services = data.get("services")
    if not isinstance(services, list) or not services or not all(isinstance(s, str) for s in services):
        raise ConfigError(f"{path}: 'services' must be a non-empty list of service names")
    return Settings(
        _text(data, "framework", str(path)),
        tuple(services),
        _text(data, "prowler_version", str(path)),
        _text(data, "localstack_image", str(path)),
    )
