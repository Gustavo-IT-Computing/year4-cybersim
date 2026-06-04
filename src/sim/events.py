from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any

# different types of events that can happen during the simulation
class EventType(str, Enum):
    TICK = "tick" # represents time progression in the sim.
    INFECT_ATTEMPT = "infect_attempt" # malware tried to infect a node
    INFECT_SUCCESS = "infect_success" # infection was successful
    QUARANTINE = "quarantine" # node was isolated from the network
    PATCH = "patch" # node was patched to reduce vulnerability
    RECOMMENDATION = "recommendation" # node was recommended to suggest action
    LOGIN_ATTEMPT = "login_attempt" # attempt to log into a node/system
    LOGIN_SUCCESS = "login_success" # login attempt was successful
    DOS_ATTACK = "dos_attack" # denial of service attack targeting a node
    SERVICE_DOWN = "service_down" # service is unavailable


@dataclass
# represents a single event happening during the simulation
class SimEvent:
    tick: int  # simulation tick when the event happened
    event_type: EventType # type of event
    source: Optional[str] = None # node that triggered the event
    target: Optional[str] = None # node affected by the event
    severity: int = 1  # importance level from 1 to 5
    details: Dict[str, Any] = field(default_factory=dict) # dictionary