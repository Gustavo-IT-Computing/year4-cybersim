from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List
import random
import uuid
from sim.models import Node, NodeState
from sim.events import SimEvent, EventType
from sim.analysis.metrics import collect_metrics, snapshot_state
from sim.defense.defense_manager import apply_defense
from sim.decision_engine import soc_decision_prompt, apply_decision
from sim.analysis.score_tracker import ScoreTracker
from sim.security.threat_pipeline import analyze_threat
from data.db import DB
from sim.analysis.ai_engine import generate_soc_recommendation

# simple structure to hold nodes and their connections
@dataclass
class Network:
    nodes: Dict[str, Node]
    edges: Dict[str, List[str]]

    # return neighbors of a node
    def neighbors(self, node_id: str) -> List[str]:
        return self.edges.get(node_id, [])

class SimulationEngine:

    def __init__(
            self,
            network,
            defense_mode: str = "hybrid",
            intensity: str = "medium",
            seed: int = 42
    ):

        # main simulation setup
        self.network = network
        self.tick = 0

        # random generator (same results every run if seed is fixed)
        self.rng = random.Random(seed)

        # unique id for this run
        self.run_id = str(uuid.uuid4())

        # defense settings
        self.defense_mode = defense_mode
        self.defense_delay = 10  # defenses only start after some time

        # tracking everything that happens
        self.history = []
        self.state_history = []
        self.events_log = []
        self.infection_edges = []

        # attack settings
        self.current_attack = "malware"
        self.intensity = intensity

        # used to control timing of some actions
        self.last_restart_tick = -10
        self.last_soc_tick = -10

        # scoring system
        self.scorer = ScoreTracker(len(self.network.nodes))

        # stats about detection
        self.detection_stats = {
            "events_analyzed": 0,
            "suspicious": 0,
            "malicious": 0,
            "harmless": 0,
            "quarantined": 0,
            "investigated": 0
        }

    # move simulation forward one step
    def step(self) -> SimEvent:
        self.tick += 1
        return SimEvent(
            tick=self.tick,
            event_type=EventType.TICK,
            severity=1
        )

    # count how many nodes are in a specific state
    def count_state(self, state: NodeState) -> int:
        return sum(1 for n in self.network.nodes.values() if n.state == state)

    # create initial threat intelligence info
    def get_threat_intel(self) -> dict:

        origin_node = None

        # find first infected node as origin
        for node, obj in self.network.nodes.items():
            if obj.state == NodeState.INFECTED:
                origin_node = node
                break

        return {
            "origin_node": origin_node or "Unknown",
            "attack_type": self.current_attack.upper(),
            "vector": getattr(self, "attack_origin", "Phishing / Malware"),
            "first_seen_tick": self.tick
        }

    # decide which phase the attack is in
    def get_attack_phase(self, metrics: dict) -> str:

        infected = metrics["infected"]
        risk = metrics["risk"]

        if infected == 0:
            return "Recovery"

        elif infected < 5:
            return "Initial Compromise"

        elif infected < 10:
            return "Containment"

        elif infected < 15:
            return "Lateral Movement"

        elif infected >= 15 and risk > 50:
            return "Outbreak"

        return "Unknown"

    # main loop of the simulation
    def run(self, steps: int, scenario_fn, db, soc_enabled=True):

        from sim.defense.recommender import recommendation_engine

        self.db = db

        # reset everything before starting
        self.history = []
        self.state_history = []
        self.events_log = []
        self.tick = 0
        self.last_soc_tick = -10

        for _ in range(steps):

            # advance time
            tick_event = self.step()
            db.log_event(self.run_id, tick_event)

            # reset node flags
            for node in self.network.nodes.values():
                node.checked = False

            # generate attack events
            attack_events = scenario_fn(self)
            self.events_log.extend(attack_events)

            # log them in database
            for e in attack_events:
                db.log_event(self.run_id, e)

            # process only infection events
            for e in attack_events:

                if getattr(e, "event_type", None) != EventType.INFECT_SUCCESS:
                    continue

                target_node = self.network.nodes.get(e.target)

                if not target_node:
                    continue

                if getattr(target_node, "checked", False):
                    continue

                target_node.checked = True

                # analyze threat and decide what to do
                result = analyze_threat(target_node, db, self.run_id, self)

                if result:
                    self.detection_stats["events_analyzed"] += 1

                    verdict = result.get("verdict")
                    action = result.get("action")

                    # update stats
                    if verdict == "malicious":
                        self.detection_stats["malicious"] += 1
                    elif verdict == "suspicious":
                        self.detection_stats["suspicious"] += 1
                    else:
                        self.detection_stats["harmless"] += 1

                    if action == "quarantine":
                        self.detection_stats["quarantined"] += 1
                    elif action == "investigate":
                        self.detection_stats["investigated"] += 1

                # store ai decisions for later use
                if result:
                    if not hasattr(self, "ai_decisions"):
                        self.ai_decisions = []

                    self.ai_decisions.append({
                        "tick": self.tick,
                        "node": target_node.node_id,
                        "confidence": result.get("confidence"),
                        "action": result.get("action"),
                        "reasons": result.get("reasons", [])
                    })

            # apply defense logic after delay
            defense_events = []

            if (
                    self.defense_mode != "none"
                    and self.tick > self.defense_delay
            ):

                before_metrics = collect_metrics(self)

                defense_events = apply_defense(
                    self,
                    self.defense_mode
                )

                after_metrics = collect_metrics(self)

                delta = (
                        before_metrics["infected"]
                        - after_metrics["infected"]
                )

                if defense_events:
                    print(f"[DEFENSE] Applied {self.defense_mode} defense")

            self.events_log.extend(defense_events)

            for e in defense_events:
                db.log_event(self.run_id, e)

            # generate ai recommendations
            rec_events = recommendation_engine(self)
            self.events_log.extend(rec_events)

            for e in rec_events:
                db.log_event(self.run_id, e)

            # update nodes over time
            for node in self.network.nodes.values():

                # chance to recover from quarantine (infection resurges)
                if node.state == NodeState.QUARANTINED and self.rng.random() < 0.1:
                    node.state = NodeState.CLEAN

                # chance to lose patch protection
                elif node.state == NodeState.PATCHED and self.rng.random() < 0.05:
                    node.state = NodeState.CLEAN

                # always update risk score
                node.update_risk()

            # collect metrics for this step
            metrics = collect_metrics(self)
            snapshot = snapshot_state(self)

            self.scorer.update_peak(metrics["infected"])

            # set threat intel at start
            if self.tick == 1:
                self.threat_intel = self.get_threat_intel()

            # soc interaction (user decision)
            if soc_enabled:

                threshold = int(len(self.network.nodes) * 0.3)

                if (
                    metrics["infected"] >= threshold
                    and self.tick - self.last_soc_tick >= 5
                ):
                    print("\n[INFO] SOC intervention triggered")

                    before = metrics["infected"]

                    recommendation = generate_soc_recommendation(self, metrics)

                    choice = soc_decision_prompt(self, recommendation)
                    apply_decision(self, choice)

                    updated_metrics = collect_metrics(self)
                    after = updated_metrics["infected"]

                    ai_decisions = getattr(self, "ai_decisions", [])

                    latest_ai = ai_decisions[-1] if ai_decisions else {}

                    self.scorer.evaluate_decision(
                        before,
                        after,
                        self.tick,
                        confidence=latest_ai.get("confidence", 50)
                    )

                    self.last_soc_tick = self.tick

            # detect critical situation
            if metrics["infected"] > len(self.network.nodes) * 0.4:
                print("CRITICAL: Possible ransomware outbreak detected!")

            # store history
            self.history.append(metrics)
            self.state_history.append(snapshot)

            print(metrics)

            db.commit()

        # finalize score at the end
        self.scorer.finalize(self.history[-1])