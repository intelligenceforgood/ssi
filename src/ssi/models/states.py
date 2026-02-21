"""Agent state machine definitions for active site investigation.

Ported from AWH's state machine with SSI-specific extensions.
"""

from enum import Enum


class AgentState(str, Enum):
    """High-level states in the scam site investigation workflow."""

    INIT = "INIT"
    LOAD_SITE = "LOAD_SITE"
    FIND_REGISTER = "FIND_REGISTER"
    FILL_REGISTER = "FILL_REGISTER"
    SUBMIT_REGISTER = "SUBMIT_REGISTER"
    CHECK_EMAIL_VERIFICATION = "CHECK_EMAIL_VERIFICATION"
    NAVIGATE_DEPOSIT = "NAVIGATE_DEPOSIT"
    EXTRACT_WALLETS = "EXTRACT_WALLETS"
    COMPLETE = "COMPLETE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


# States where screenshots are captured (key milestones)
MILESTONE_SCREENSHOT_STATES = {
    AgentState.LOAD_SITE,
    AgentState.FIND_REGISTER,
    AgentState.FILL_REGISTER,
    AgentState.NAVIGATE_DEPOSIT,
    AgentState.EXTRACT_WALLETS,
    AgentState.ERROR,
}

# Terminal states reachable from any state (human skip, error, completion)
TERMINAL_STATES = {AgentState.COMPLETE, AgentState.SKIPPED, AgentState.ERROR}

# Normal state transitions (TERMINAL_STATES are always valid in addition to these)
STATE_TRANSITIONS: dict[AgentState, list[AgentState]] = {
    AgentState.INIT: [AgentState.LOAD_SITE],
    AgentState.LOAD_SITE: [AgentState.FIND_REGISTER],
    AgentState.FIND_REGISTER: [AgentState.FILL_REGISTER, AgentState.NAVIGATE_DEPOSIT],
    AgentState.FILL_REGISTER: [AgentState.SUBMIT_REGISTER],
    AgentState.SUBMIT_REGISTER: [
        AgentState.CHECK_EMAIL_VERIFICATION,
        AgentState.NAVIGATE_DEPOSIT,
    ],
    AgentState.CHECK_EMAIL_VERIFICATION: [AgentState.NAVIGATE_DEPOSIT],
    AgentState.NAVIGATE_DEPOSIT: [AgentState.EXTRACT_WALLETS],
    AgentState.EXTRACT_WALLETS: [AgentState.COMPLETE],
}
