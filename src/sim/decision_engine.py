from sim.models import NodeState

# display SOC recommendation and ask user for response
def soc_decision_prompt(engine, recommendation):

    print("\nSOC ALERT")
    print(f"Tick {engine.tick}: Infection spreading")

    print("\nAI Recommendation:")
    print(f"- {recommendation['action'].capitalize()}")

    print(f"Why: {recommendation['reason']}")

    print("\nChoose action:")
    print("1. Isolate nodes")
    print("2. Patch systems")
    print("3. Do nothing")

    while True:

        choice = input("Enter choice (1-3): ").strip()

        if choice in ["1", "2", "3"]:
            return choice
        print("Invalid choice. Try again.")

# apply user SOC decision
def apply_decision(engine, choice):

    nodes = list(engine.network.nodes.values())

    # isolate infected systems
    if choice == "1":

        infected = [
            n for n in nodes
            if n.state == NodeState.INFECTED
        ]

        if not infected:
            print("[ACTION] No infected nodes to isolate")
            return

        to_isolate = max(1, int(len(infected) * 0.6))

        for node in engine.rng.sample(infected, to_isolate):
            node.state = NodeState.QUARANTINED
        print(f"[ACTION] Isolated {to_isolate} infected nodes")

    # patch clean systems
    elif choice == "2":

        candidates = [
            n for n in nodes
            if n.state == NodeState.CLEAN
        ]

        if not candidates:
            print("[ACTION] No clean nodes available for patching")
            return

        to_patch = max(1, int(len(candidates) * 0.4))

        for node in engine.rng.sample(candidates, to_patch):
            node.state = NodeState.PATCHED
        print(f"[ACTION] Patched {to_patch} systems")

    # no action
    elif choice == "3":
        print("[ACTION] No action taken")

    else:
        print("[ERROR] Invalid action")