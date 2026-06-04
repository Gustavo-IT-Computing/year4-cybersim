from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any

# possible states a node can have during the simulation
class NodeState(str, Enum):
    CLEAN = "clean" # node is not infected
    INFECTED = "infected" # node is infected
    QUARANTINED = "quarantined" # node is isolated
    PATCHED = "patched" # node is patched, reducing its vulnerability

# different device types inside the network
class DeviceType(str, Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    DATABASE = "database"
    IOT = "iot"

# network zones used in the simulation
class NetworkZone(str, Enum):
    DMZ = "dmz"
    INTERNAL = "internal"
    IOT = "iot"

# representing a node in the network
@dataclass
class Node:
    node_id: str
    vuln_level: float
    zone: NetworkZone
    device_type: DeviceType
    state: NodeState = NodeState.CLEAN
    meta: Dict[str, Any] = field(default_factory=dict)

    role: str = "workstation" # descriptive role
    criticality: str = "medium" # business importance
    risk_score: float = 0.0
    under_investigation: bool = False

    active_attacks: set = field(default_factory=set)

    # update risk score based on state and vulnerability
    def update_risk(self):

        base = self.vuln_level # base risk from vulnerability

        if self.state == NodeState.INFECTED:
            self.risk_score = 1.0 # maximum risk

        elif self.state == NodeState.QUARANTINED:
            self.risk_score = 0.2 # reduced risk

        elif self.state == NodeState.PATCHED:
            self.risk_score = max(0.05, base * 0.3) # lower risk after patching

        else:
            self.risk_score = base # normal risk