from sim.analysis.ai_engine import (calculate_severity,generate_attack_insights,generate_response_plan,generate_attack_narrative)
import matplotlib.pyplot as plt

# print SOC decision history
def print_decision_log(engine):

    decisions = engine.scorer.decisions

    if not decisions:

        print("\nDecision Log:")
        print("No SOC decisions were made.")
        return

    print("\nDecision Log:")

    for d in decisions:

        print(
            f"- Tick {d['tick']} → {d['result']} "
            f"({d['before']} → {d['after']}, {d['impact']:+})"
        )

# generate final simulation report
def generate_final_report(engine):

    final = engine.history[-1]

    severity = calculate_severity(final,engine.history,engine)

    insights = generate_attack_insights(engine)

    playbook = generate_response_plan(engine,final)

    narrative = generate_attack_narrative(engine)

    origin = getattr(
        engine,
        "threat_intel",
        {}
    ).get("origin_node", "Unknown")

    print("\n" + "=" * 60)
    print("CyberSim Incident Report")
    print("=" * 60)

    print("\nSummary")
    print(f"Attack Type: {engine.current_attack.upper()}")
    print(f"Origin: {origin}")
    print(f"Severity: {severity}")

    print("\nAttack Summary")
    print(narrative)

    print("\nFinal State")
    print(f"Infected: {final['infected']}")
    print(f"Quarantined: {final['quarantined']}")
    print(f"Patched: {final['patched']}")
    print(f"Clean: {final['clean']}")
    print(f"Risk Score: {final['risk']:.2f}")

    print("\nKey Insights")

    for i in insights:
        print(f"- {i}")

    print("\nResponse Actions")

    for a in playbook:
        print(f"- {a}")

    print("\nDecisions")
    print_decision_log(engine)

    print("\nAI Detection Insights")

    shown = 0

    for d in getattr(engine, "ai_decisions", [])[:5]:

        print(f"\nNode: {d['node']}")
        print(f"Confidence: {d['confidence']}%")

        for r in d["reasons"]:
            print(f"- {r}")

        shown += 1

    if shown == 0:
        print("No AI insights available")

    # final outcome
    if final["infected"] == 0:
        outcome = "Threat Eliminated"

    elif final["infected"] <= 2:
        outcome = "Residual Infection (Contained)"

    else:
        outcome = "Threat Active"

    print("\nOutcome")
    print(outcome)

    print("=" * 60)

# count how many events came from each attack type
def get_attack_distribution(engine):

    counts = {
        "malware": 0,
        "dos": 0,
        "bruteforce": 0
    }

    for e in engine.events_log:

        attack = e.details.get("attack_type")

        if attack in counts:
            counts[attack] += 1

    return counts

# count how many nodes are in each final state
def get_node_state_distribution(engine):

    states = {
        "Clean": 0,
        "Infected": 0,
        "Patched": 0,
        "Quarantined": 0
    }

    for node in engine.network.nodes.values():

        state = node.state.name

        if state == "CLEAN":
            states["Clean"] += 1

        elif state == "INFECTED":
            states["Infected"] += 1

        elif state == "PATCHED":
            states["Patched"] += 1

        elif state == "QUARANTINED":
            states["Quarantined"] += 1

    return states

# generate visual report
def generate_visual_report(engine):

    final = engine.history[-1]

    severity = calculate_severity(final, engine.history, engine)

    insights = generate_attack_insights(engine)

    playbook = generate_response_plan(engine, final)

    peak = max(h["infected"] for h in engine.history)

    # infected over time
    infected_history = [
        h["infected"]
        for h in engine.history
    ]

    # attack distribution
    attack_counts = get_attack_distribution(engine)

    # node states
    node_states = get_node_state_distribution(engine)

    # MAIN FIGURE
    fig = plt.figure(figsize=(15, 8))

    # REPORT PANEL

    ax1 = plt.subplot2grid((2, 3), (0, 0), rowspan=2)

    ax1.axis("off")

    ax1.text(
        0,
        1,
        "CyberSim Incident Report",
        fontsize=18,
        weight="bold"
    )

    ax1.text(
        0,
        0.82,
        f"Attack: {engine.current_attack.upper()}\n"
        f"Defense: {engine.defense_mode.upper()}\n"
        f"Severity: {severity}\n"
        f"Peak Infection: {peak}",
        fontsize=12
    )

    ax1.text(
        0,
        0.55,
        "Final Metrics:\n"
        f"Infected: {final['infected']}\n"
        f"Quarantined: {final['quarantined']}\n"
        f"Patched: {final['patched']}\n"
        f"Risk: {final['risk']:.2f}",
        fontsize=12
    )

    ax1.text(
        0,
        0.28,
        "Insights:\n" +
        "\n".join(f"- {i}" for i in insights),
        fontsize=11
    )

    # INFECTED OVER TIME
    ax2 = plt.subplot2grid((2, 3), (0, 1))

    ax2.plot(infected_history)

    ax2.set_title("Infected Nodes Over Time")
    ax2.set_xlabel("Tick")
    ax2.set_ylabel("Infected Nodes")

    # ATTACK DISTRIBUTION
    ax3 = plt.subplot2grid((2, 3), (0, 2))

    ax3.bar(
        attack_counts.keys(),
        attack_counts.values()
    )

    ax3.set_title("Attack Type Distribution")

    # NODE STATE DISTRIBUTION
    ax4 = plt.subplot2grid((2, 3), (1, 1))

    ax4.pie(
        node_states.values(),
        labels=node_states.keys(),
        autopct='%1.1f%%'
    )

    ax4.set_title("Final Node States")

    # SCORE PANEL
    ax5 = plt.subplot2grid((2, 3), (1, 2))

    ax5.axis("off")

    if final["infected"] == 0:
        outcome = "Threat Eliminated"

    elif final["infected"] <= 2:
        outcome = "Residual Infection"

    else:
        outcome = "Threat Active"

    ax5.text(
        0,
        0.8,
        f"Score: {engine.scorer.score}\n"
        f"Grade: {engine.scorer.grade}\n"
        f"Decisions: "
        f"{engine.scorer.good_decisions}/"
        f"{engine.scorer.total_decisions}",
        fontsize=14
    )

    ax5.text(
        0,
        0.45,
        f"Outcome:\n{outcome}",
        fontsize=16,
        weight="bold"
    )

    ax5.text(
        0,
        0.15,
        "Recommended Actions:\n" +
        "\n".join(f"- {a}" for a in playbook),
        fontsize=11
    )

    plt.tight_layout()
    plt.show()
