"""
Configuration Store Module

Provides storage and retrieval of model preferences.

Configuration File Format:
-------------------------
Location: ~/.astrava/config.json

Structure:
{
    "active_model": "xploiter/pentester"
}
"""

import os
import json
from pathlib import Path


# Configuration file location
CONFIG_DIR = Path.home() / ".astrava"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _ensure_config_directory() -> None:
    """Create ~/.astrava/ directory with proper permissions."""
    if not CONFIG_DIR.exists():
        CONFIG_DIR.mkdir(mode=0o700, parents=True)
    else:
        os.chmod(CONFIG_DIR, 0o700)


def _set_config_file_permissions() -> None:
    """Set config file permissions to 600."""
    if CONFIG_FILE.exists():
        os.chmod(CONFIG_FILE, 0o600)


def _create_default_config() -> dict:
    """Create default configuration structure."""
    return {
        "active_model": "xploiter/pentester"
    }


def load_config() -> dict:
    """
    Load configuration from ~/.astrava/config.json.
    Handles missing or corrupted files by creating default configuration.

    Returns:
        dict: Configuration dictionary
    """
    _ensure_config_directory()

    if not CONFIG_FILE.exists():
        config = _create_default_config()
        save_config(config)
        return config

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
        print(f"Warning: Configuration file corrupted ({e}), creating default config")
        config = _create_default_config()
        save_config(config)
        return config


def save_config(config: dict) -> bool:
    """
    Write configuration to ~/.astrava/config.json.

    Args:
        config: Configuration dictionary

    Returns:
        bool: True if save successful, False otherwise
    """
    try:
        _ensure_config_directory()

        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

        _set_config_file_permissions()
        return True

    except Exception as e:
        print(f"Error: Failed to save configuration: {e}")
        return False


def get_active_model() -> tuple:
    """
    Get the currently active Ollama model name.

    Returns:
        tuple[str, str]: ("ollama", model_name)
    """
    config = load_config()
    model = config.get("active_model", "xploiter/pentester")
    return ("ollama", model)


def set_active_model(mode: str, model: str) -> bool:
    """
    Save active model selection (Ollama only).

    Args:
        mode: Ignored, always "ollama"
        model: Ollama model name

    Returns:
        bool: True if save successful, False otherwise
    """
    config = load_config()
    config["active_model"] = model
    return save_config(config)
