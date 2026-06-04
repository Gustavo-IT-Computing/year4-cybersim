from matplotlib import pyplot as plt
from sim.engine import Network, SimulationEngine  # core simulation classes
from sim.network.generator import generate_network  # network creation
from sim.analysis.dashboard import run_dashboard  # dashboard view
from sim.scenarios.scenario_manager import get_scenario  # scenario selection
from sim.analysis.replay import print_attack_chain  # attack replay
from sim.analysis.final_report import generate_final_report, generate_visual_report  # final report
from data.db import DB  # database handler
import os
import copy

# display intro and let user choose scenario
def show_intro():

    print("\n==============================")
    print("CyberSim Platform")
    print("==============================\n")

    print("Select Simulation Mode:\n")
    print("1. Baseline (Malware + Hybrid Defense)")
    print("2. Compare Defense vs No Defense (Worst Case)")
    print("3. Advanced Scenario (Multi-Attack)\n")

    while True:
        choice = input("Enter choice (1-3): ").strip()

        # map user input to scenario names
        mapping = {
            "1": "baseline",
            "2": "compare",
            "3": "advanced"
        }

        if choice in mapping:
            return mapping[choice]

        print("Invalid choice. Please enter 1, 2 or 3.\n")

# show explanation before simulation starts
def demo_explanation(scenario_name, network_size):

    print("\n[INFO] Starting Cyber Attack Simulation...\n")

    print(f"[INFO] Scenario Selected: {scenario_name.upper()}")
    print(f"[INFO] Network Size: {network_size} nodes")
    print(f"[INFO] Duration: {network_size} ticks\n")

    print("Legend:")
    print(" - Red   = Infected node")
    print(" - Orange = Quarantined node")
    print(" - Blue  = Patched node")
    print(" - Green = Low risk")
    print(" - Yellow = Medium risk\n")

    print("[INFO] AI Recommendations will guide defense decisions.\n")

#  compare with and without defense scenarios
def run_comparison(db, network_size):

    print("\n[INFO] Running comparison: Defense vs No Defense...\n")

    # generate SAME network for fair comparison
    nodes, edges = generate_network(size=network_size)

    # WITH DEFENSE
    baseline = get_scenario("baseline")
    net1 = Network(
        copy.deepcopy(nodes),
        copy.deepcopy(edges)
    )
    engine1 = SimulationEngine(net1, defense_mode=baseline["defense"])
    engine1.current_attack = baseline["attack"]
    engine1.run(network_size, baseline["fn"], db)

    # WITHOUT DEFENSE
    no_def = get_scenario("no_defense")
    net2 = Network(
        copy.deepcopy(nodes),
        copy.deepcopy(edges)
    )

    engine2 = SimulationEngine(
        net2,
        defense_mode="none"
    )

    engine2.current_attack = no_def["attack"]

    # disable SOC completely
    engine2.run(
        network_size,
        no_def["fn"],
        db,
        soc_enabled=False
    )

    # results
    print("\n=== COMPARISON RESULTS ===\n")

    print("WITH DEFENSE:")
    print(f"- Final infected: {engine1.history[-1]['infected']}")
    print(f"- Peak infected: {max(h['infected'] for h in engine1.history)}")
    print(f"- Final risk: {engine1.history[-1]['risk']}")

    print("\nWITHOUT DEFENSE:")
    print(f"- Final infected: {engine2.history[-1]['infected']}")
    print(f"- Peak infected: {max(h['infected'] for h in engine2.history)}")
    print(f"- Final risk: {engine2.history[-1]['risk']}")

    print("\n=== INSIGHT ===")

    if (
            max(engine1.history, key=lambda x: x["infected"])["infected"]
            >
            max(engine2.history, key=lambda x: x["infected"])["infected"]
    ):

        print("- Defense reacts after infection, not before it")
        print("- Temporary spikes can still occur before containment")

    print("- Defense reduced infection duration significantly")
    print("- Without defense, infection persists and dominates the network")
    print("- Recovery speed is as important as prevention")
    # extract infection curves

    def_curve = [h["infected"] for h in engine1.history]

    nodef_curve = [h["infected"] for h in engine2.history]

    ticks = list(range(len(def_curve)))

    plt.figure()

    plt.plot(ticks, def_curve, label="With Defense")

    plt.plot(ticks, nodef_curve, label="No Defense")

    plt.xlabel("Tick")

    plt.ylabel("Infected Nodes")

    plt.title("Defense Impact Comparison")

    plt.legend()

    plt.show()

#  creating readable conclusions
def generate_insights(engine):

    history = engine.history
    peak = max(m["infected"] for m in history)
    final = history[-1]
    total = len(engine.network.nodes)

    print("\n=== AI INSIGHTS ===")

    # Infection severity
    if peak > total * 0.7:
        print("- Severe outbreak: most of the network was compromised")
    elif peak > total * 0.4:
        print("- Moderate outbreak: significant spread across the network")
    else:
        print("- Limited spread: attack contained early")

    # Defense effectiveness
    if final["infected"] == 0:
        print("- Defense successfully eliminated the threat")
    elif final["infected"] < peak:
        print("- Defense reduced infection but did not fully eliminate it")
    else:
        print("- Defense ineffective: infection persisted")

    # Risk evolution
    if final["risk"] == 0:
        print("- Network risk fully mitigated by end of simulation")
    elif final["risk"] < 20:
        print("- Residual risk remains but is under control")
    else:
        print("- High risk remains in the network")

    # Operational impact
    if final["quarantined"] > 10:
        print("- High number of quarantined systems may impact operations")

    if final["patched"] > 5:
        print("- Patching played a key role in containment")

    print()

# main function to run the simulation
def main() -> None:

    # select scenario
    scenario_name = show_intro()

    while True:

        try:
            network_size = int(input("\nEnter network size (10-200): "))

            if 10 <= network_size <= 200:
                break

            print("Choose between 10 and 200.") # choose the network size

        except ValueError:
            print("Please enter a valid number.")

    if os.path.exists("cybersim.db"):
        os.remove("cybersim.db")

    # initialize database
    db = DB("cybersim.db")
    db.connect()

    if scenario_name == "compare":
        run_comparison(db, network_size)
        db.close()
        return

    scenario = get_scenario(scenario_name)

    demo_explanation(scenario_name, network_size)

    # generate network
    nodes, edges = generate_network(size=network_size)
    network = Network(nodes, edges)

    # create simulation engine
    engine = SimulationEngine(
        network,
        defense_mode=scenario["defense"],
        intensity="medium"
    )

    # set initial attack type
    engine.current_attack = scenario["attack"]

    # run simulation
    engine.run(
        steps=network_size,
        scenario_fn=scenario["fn"],
        db=db
    )

    print("\n=== SIMULATION COMPLETE ===")
    print("Run ID:", engine.run_id)

    # show results
    run_dashboard(engine, db)  # interactive dashboard

    generate_final_report(engine)  # summary report
    generate_visual_report(engine)
    print_attack_chain(engine)  # attack path

    # close database connection
    db.close()

# run program
if __name__ == "__main__":
    main()