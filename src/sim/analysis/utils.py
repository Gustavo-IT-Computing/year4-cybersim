# convert an event into a simple explanation that is easy to read
def explain_event(event):

    et = event.event_type.name

    # map each event type to a human explanation
    if et == "INFECT_SUCCESS":
        return f"Malware execution confirmed on {event.target}"

    if et == "INFECT_ATTEMPT":
        return f"Propagation attempt detected targeting {event.target}"

    if et == "LOGIN_SUCCESS":
        return f"Unauthorized access gained on {event.target}"

    if et == "LOGIN_ATTEMPT":
        return f"Login attempt detected on {event.target}"

    if et == "DOS_ATTACK":
        return f"Service disruption affecting {event.target}"

    if et == "QUARANTINE":
        return f"{event.target} isolated from network"

    if et == "PATCH":
        return f"{event.target} patched and secured"

    # special case for AI recommendations
    if et == "RECOMMENDATION":

        action = event.details.get("action", "monitor")

        return f"AI recommended action: {action}"

    # fallback if event type is unknown
    return f"{et} → {event.target}"

# generate short alert messages
def generate_alert(event):

    et = event.event_type.name

    # only some events create alerts
    if et == "INFECT_SUCCESS":
        return f"[ALERT] {event.target}: Malware execution confirmed"

    if et == "LOGIN_SUCCESS":
        return f"[ALERT] {event.target}: Unauthorized access detected"

    if et == "DOS_ATTACK":
        return f"[ALERT] {event.target}: Service disruption detected"

    if et == "QUARANTINE":
        return f"[INFO] {event.target}: Node isolated for containment"

    # no alert for other events
    return ""

# generate explanation for why a node was marked malicious or harmless
def explain_detection(node_id, verdict, sources, engine):

    reasons = []
    confidence = 0

    # gather verdicts from all sources
    db = sources.get("db")
    api = sources.get("api")
    scan = sources.get("scan")

    # each source contributes to confidence
    if db == "malicious":
        reasons.append("Known threat in internal database")
        confidence += 40

    if api == "malicious":
        reasons.append("Flagged by external threat intelligence API")
        confidence += 30

    if scan == "malicious":
        reasons.append("Malware signature detected by scan engine")
        confidence += 50

    if scan == "harmless":
        reasons.append("Scan engine did not detect malware")

    # check nearby infected nodes
    try:

        neighbors = engine.network.edges.get(node_id, [])

        risky_neighbors = sum(
            1
            for n in neighbors
            if engine.network.nodes[n].state.name == "INFECTED"
        )

        if risky_neighbors > 0:

            reasons.append(
                f"Connected to {risky_neighbors} infected nodes"
            )

            # nearby infected nodes increase suspicion
            confidence += min(20, risky_neighbors * 5)

    except Exception:
        pass

    # cap confidence at 100
    confidence = min(confidence, 100)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons
    }