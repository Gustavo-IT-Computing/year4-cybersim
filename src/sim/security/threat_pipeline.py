import random
from sim.models import NodeState
from sim.threat.intel_api import check_with_api


# simulate a local scan result for a node
def run_local_scan(node):

    # infected nodes are likely malicious
    if node.state == NodeState.INFECTED:
        return (
            "malicious"
            if random.random() < 0.8
            else "harmless"
        )

    # clean nodes are harmless
    return "harmless"


# analyze a node and decide response
def analyze_threat(node, db, run_id, engine):

    # ignore contained nodes
    if node.state == NodeState.QUARANTINED:
        return {
            "action": "ignore",
            "verdict": "contained",
            "confidence": 0,
            "reasons": []
        }

    # ignore nodes without infection
    if node.state != NodeState.INFECTED:
        return {
            "action": "ignore",
            "verdict": "no_event",
            "confidence": 0,
            "reasons": []
        }

    # 1. choose indicator
    indicator = (
        "44d88612fea8a8f36de82e1278abb02f"
        if random.random() < 0.3
        else node.node_id
    )

    db_verdict = None
    api_verdict = None
    scan_verdict = None
    source = "unknown"

    # 2. internal threat database
    existing = db.get_threat(indicator)

    if existing:

        db_verdict = existing["verdict"]
        source = "db"

        print(
            f"[DB] Known threat: "
            f"{indicator} → {db_verdict}"
        )

    else:
        print(f"[DB] Unknown indicator: {indicator}")

    # 3. external threat intelligence API
    if not db_verdict or db_verdict == "unknown":

        if random.random() > 0.5:

            api_result = check_with_api(indicator)

            api_verdict = api_result.get(
                "verdict",
                "unknown"
            )

            source = "api"

        else:
            api_verdict = "unknown"

    # 4. local malware scan
    scan_verdict = run_local_scan(node)

    if scan_verdict == "malicious":
        print(f"[SCAN] Malware detected on {node.node_id}")

    else:
        print(f"[SCAN] No threat on {node.node_id}")

    # 5. confidence calculation
    confidence = 0
    reasons = []

    # database has strongest weight
    if db_verdict == "malicious":
        confidence += 60
        reasons.append(
            "Known threat in internal database"
        )

    elif db_verdict == "harmless":
        confidence -= 30

    # API adds medium confidence
    if api_verdict == "malicious":
        confidence += 25
        reasons.append(
            "Flagged by external threat intelligence API"
        )

    elif api_verdict == "harmless":
        confidence -= 10

    # local scan adds support
    if scan_verdict == "malicious":
        confidence += 20
        reasons.append(
            "Malware signature detected by scan engine"
        )

    # network context
    infected_neighbors = sum(
        1
        for n_id in engine.network.neighbors(
            node.node_id
        )
        if engine.network.nodes[n_id].state
        == NodeState.INFECTED
    )

    if infected_neighbors > 0:

        spread_score = min(
            20,
            infected_neighbors * 5
        )

        confidence += spread_score

        reasons.append(
            f"Connected to "
            f"{infected_neighbors} infected nodes"
        )

    # keep confidence in range
    confidence = max(
        0,
        min(confidence, 100)
    )

    # 6. final verdict
    if confidence >= 70:
        final_verdict = "malicious"

    elif confidence >= 40:
        final_verdict = "suspicious"

    else:
        final_verdict = "harmless"

    # 7. choose action
    if final_verdict == "malicious":

        action = "quarantine"
        risk_level = "HIGH"

    elif final_verdict == "suspicious":

        if confidence >= 60:
            action = "investigate"
            risk_level = "MEDIUM"

        else:
            action = "monitor"
            risk_level = "LOW"

    else:

        action = "monitor"
        risk_level = "LOW"

    # 8. apply network effects
    if action == "quarantine":

        node.state = NodeState.QUARANTINED

        # raise neighbour risk
        for n_id in engine.network.neighbors(
            node.node_id
        ):

            neighbor = engine.network.nodes.get(n_id)

            if (
                neighbor
                and neighbor.state
                == NodeState.CLEAN
            ):
                neighbor.risk_score = min(
                    1.0,
                    neighbor.risk_score + 0.2
                )

        print(
            f"[NETWORK] Risk propagated "
            f"from {node.node_id}"
        )

    elif action == "investigate":

        if not hasattr(
            node,
            "under_investigation"
        ):
            node.under_investigation = True

        node.risk_score = min(
            1.0,
            node.risk_score + 0.1
        )

    # 9. store confirmed threat
    if final_verdict == "malicious":
        db.log_threat(
            run_id,
            node.node_id,
            indicator,
            final_verdict,
            source
        )

    # 10. attach explanation
    explanation = {
        "confidence": confidence,
        "reasons": reasons
    }

    if engine.events_log:

        event = engine.events_log[-1]

        if (
            hasattr(event, "details")
            and event.details is not None
        ):
            event.details["explanation"] = explanation

    # output logs
    if final_verdict == "malicious":
        print("[ALERT]")

    print(f"Node: {node.node_id}")
    print(f"Indicator: {indicator}")
    print(f"Suggested Action: {action.upper()}")
    print(f"Confidence: {confidence}%")
    print(f"Risk Level: {risk_level}")

    print("Reason:")

    for r in reasons:
        print(f"- {r}")

    print(
        f"Sources: "
        f"DB={db_verdict}, "
        f"API={api_verdict}, "
        f"SCAN={scan_verdict}"
    )

    return {
        "action": action,
        "verdict": final_verdict,
        "confidence": confidence,
        "reasons": reasons
    }