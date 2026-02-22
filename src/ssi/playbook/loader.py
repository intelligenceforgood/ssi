"""Playbook loader — load playbooks from JSON files on disk.

Playbook JSON files live in a configurable directory (default:
``config/playbooks/``). Each ``.json`` file contains a single playbook
definition conforming to the ``Playbook`` schema.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ssi.playbook.models import Playbook

logger = logging.getLogger(__name__)


def load_playbook_from_file(path: Path) -> Playbook:
    """Load a single playbook from a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        A validated ``Playbook`` instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        pydantic.ValidationError: If the data does not conform to the schema.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return Playbook(**data)


def load_playbooks_from_dir(directory: Path | str) -> list[Playbook]:
    """Load all playbook JSON files from a directory.

    Files that fail validation are logged and skipped rather than
    aborting the entire load.

    Args:
        directory: Path to the playbooks directory.

    Returns:
        List of successfully loaded ``Playbook`` instances.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        logger.warning("Playbook directory does not exist: %s", dir_path)
        return []

    playbooks: list[Playbook] = []
    for json_file in sorted(dir_path.glob("*.json")):
        try:
            pb = load_playbook_from_file(json_file)
            playbooks.append(pb)
            logger.info("Loaded playbook %s from %s", pb.playbook_id, json_file.name)
        except Exception:
            logger.exception("Failed to load playbook from %s", json_file)
    return playbooks
