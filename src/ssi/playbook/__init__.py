"""Playbook engine — deterministic action sequences for known scam site patterns.

When a site URL matches a playbook's ``url_pattern``, the agent controller
can execute scripted steps instead of relying on vision-based LLM analysis.
This eliminates LLM cost for sites with predictable UIs (e.g., scam clusters
sharing the same frontend template).

Modules:

* ``models`` — ``Playbook``, ``PlaybookStep``, ``PlaybookStepType`` data models.
* ``matcher`` — ``PlaybookMatcher`` for URL → playbook matching.
* ``executor`` — ``PlaybookExecutor`` for running playbook steps against the browser.
* ``loader`` — Load playbooks from JSON files on disk.
"""

from ssi.playbook.executor import PlaybookExecutor
from ssi.playbook.loader import load_playbooks_from_dir
from ssi.playbook.matcher import PlaybookMatcher
from ssi.playbook.models import Playbook, PlaybookStep, PlaybookStepType

__all__ = [
    "Playbook",
    "PlaybookExecutor",
    "PlaybookMatcher",
    "PlaybookStep",
    "PlaybookStepType",
    "load_playbooks_from_dir",
]
