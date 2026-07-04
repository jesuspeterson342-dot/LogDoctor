"""Configuration loading and management."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from logdoctor.models import AppConfig

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "logdoctor"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.yml"
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
BUNDLED_RULES = [
    "default_rules.yml",
    "nginx_rules.yml",
    "python_rules.yml",
    "docker_rules.yml",
    "pacman_rules.yml",
]


def load_config(config_path: Path | None = None) -> AppConfig:
    """Load application configuration from YAML file.

    Falls back to defaults if file is missing or malformed.
    """
    path = config_path or DEFAULT_CONFIG_FILE
    if not path.exists():
        return AppConfig()

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw and isinstance(raw, dict):
            return AppConfig(**raw)
    except (yaml.YAMLError, ValidationError):
        pass

    return AppConfig()


def get_rules_dir(config: AppConfig) -> Path:
    """Resolve the directory containing rule YAML files."""
    if config.rules_path:
        custom = Path(config.rules_path)
        if custom.is_dir():
            return custom
    return DEFAULT_RULES_DIR


def ensure_config_dir() -> Path:
    """Create config directory if it does not exist. Returns the path."""
    DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_CONFIG_DIR


def write_default_config(config_path: Path | None = None) -> Path:
    """Write a default config file. Returns the path written."""
    path = config_path or DEFAULT_CONFIG_FILE
    ensure_config_dir()
    default = AppConfig()
    content = yaml.dump(default.model_dump(), default_flow_style=False, sort_keys=False)
    path.write_text(content, encoding="utf-8")
    return path


def copy_default_rules(target_dir: Path) -> list[Path]:
    """Copy bundled rule files to target_dir. Returns list of written paths."""
    target_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in BUNDLED_RULES:
        src = DEFAULT_RULES_DIR / name
        if src.exists():
            dst = target_dir / name
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            written.append(dst)
    return written


def resolve_cache_dir(config: AppConfig) -> Path:
    """Resolve cache directory, creating it if needed."""
    cache = Path(config.cache_dir) if config.cache_dir else Path.home() / ".cache" / "logdoctor"
    cache.mkdir(parents=True, exist_ok=True)
    return cache
