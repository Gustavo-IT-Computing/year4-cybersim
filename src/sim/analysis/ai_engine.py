from sim.models import NodeState

# generate severity classification for the incident
def calculate_severity(final, history, engine):

    peak = max(h["infected"] for h in history)
    total = len(engine.network.nodes)

    peak_ratio = peak / max(1, total)

    # compare infection against network size
    if peak_ratio > 0.7:
        return "HIGH (Contained)" if final["infected"] == 0 else "CRITICAL"

    elif peak_ratio > 0.4:
        return "MEDIUM (Contained)" if final["infected"] == 0 else "HIGH"

    elif final["infected"] > 0:
        return "MEDIUM"

    return "LOW"

# generate insights about attack behavior
def generate_attack_insights(engine):

    history = engine.history
    peak = max(m["infected"] for m in history)

    final = history[-1]
    total = len(engine.network.nodes)

    peak_pct = round((peak / total) * 100, 1)
    final_pct = round((final["infected"] / total) * 100, 1)

    insights = []

    insights.append(
        f"Peak infection reached {peak} nodes ({peak_pct}% of network)"
    )

    if final["infected"] == 0:
        insights.append("Threat successfully contained and removed")

    else:
        insights.append(
            f"{final['infected']} nodes remain infected ({final_pct}% of network)"
        )

    if final["risk"] < 10:
        insights.append("Overall network risk reduced to low level")

    elif final["risk"] < 25:
        insights.append("Network risk stabilized but remains elevated")

    else:
        insights.append("High residual risk detected in the network")

    reduction = peak - final["infected"]

    insights.append(
        f"Defense reduced infections by {reduction} nodes"
    )

    return insights

# generate SOC recommendation based on attack state
def generate_soc_recommendation(engine, metrics):

    infected = metrics["infected"]
    risk = metrics["risk"]

    # major outbreak
    if infected >= 15 or risk >= 60:

        return {
            "action": "quarantine",
            "reason": "Critical outbreak detected with rapid lateral movement"
        }

    # medium spread
    elif infected >= 8 or risk >= 35:

        return {
            "action": "patch",
            "reason": "Infection spreading across multiple connected systems"
        }

    # low activity
    return {
        "action": "monitor",
        "reason": "Threat activity currently stable"
    }

# generate response actions after simulation
def generate_response_plan(engine, final):

    actions = []

    infected_nodes = [
        node.node_id
        for node in engine.network.nodes.values()
        if node.state == NodeState.INFECTED
    ]

    unpatched_nodes = [
        node.node_id
        for node in engine.network.nodes.values()
        if node.state != NodeState.PATCHED
    ]

    # malware response plan
    if engine.current_attack == "malware":

        actions += [
            f"Isolate {len(infected_nodes)} infected systems",
            f"Patch {len(unpatched_nodes)} unpatched nodes",
            "Run antivirus scans across all endpoints"
        ]

    # dos response plan
    elif engine.current_attack == "dos":

        actions += [
            "Block malicious traffic sources",
            "Enable rate limiting",
            "Scale infrastructure capacity"
        ]

    # bruteforce response plan
    elif engine.current_attack == "bruteforce":

        actions += [
            "Reset compromised credentials",
            "Enable MFA across all users",
            "Audit authentication logs"
        ]

    if final["risk"] > 5:
        actions.append("Escalate incident to SOC team")

    return actions

# generate attack narrative
def generate_attack_narrative(engine):

    history = engine.history

    peak = max(h["infected"] for h in history)

    peak_tick = next(
        i for i, h in enumerate(history)
        if h["infected"] == peak
    )

    containment_tick = next(
        (
            i for i, h in enumerate(history)
            if h["infected"] == 0 and i > peak_tick
        ),
        None
    )

    origin = getattr(
        engine,
        "threat_intel",
        {}
    ).get("origin_node", "Unknown")

    attack_type = getattr(
        engine,
        "threat_intel",
        {}
    ).get("attack_type", engine.current_attack)

    # build final narrative
    narrative = (
        f"Attack originated from node {origin} using {attack_type}. "
        f"Infection peaked at {peak} nodes on tick {peak_tick + 1}. "
    )

    if containment_tick:
        narrative += f"Containment achieved by tick {containment_tick + 1}."

    else:
        narrative += "Infection was not fully contained."

    return narrative