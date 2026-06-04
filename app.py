# use non-GUI backend for flask/macOS
import matplotlib
matplotlib.use("Agg")

from flask import Flask, render_template, request, url_for

from sim.engine import Network, SimulationEngine
from sim.network.generator import generate_network
from sim.scenarios.scenario_manager import get_scenario

from data.db import DB

import matplotlib.pyplot as plt
import os

# create flask application
app = Flask(__name__)

# create charts folder if it does not exist
os.makedirs("static", exist_ok=True)

# home page route
@app.route("/", methods=["GET", "POST"])
def index():

    # results are empty before simulation runs
    result = None

    # when user submits the form
    if request.method == "POST":

        # get selected attack scenario
        scenario_name = request.form.get("scenario")

        # get selected defense strategy
        defense_mode = request.form.get("defense")

        # get user-defined network size
        network_size = int(request.form.get("network_size"))

        # keep values inside safe limits
        if network_size < 10:
            network_size = 10

        if network_size > 200:
            network_size = 200

        # load selected scenario configuration
        scenario = get_scenario(scenario_name)

        # reset database for fresh simulation
        if os.path.exists("cybersim.db"):
            os.remove("cybersim.db")

        # initialize database
        db = DB("cybersim.db")
        db.connect()

        # generate simulated network
        nodes, edges = generate_network(size=network_size)

        # create network object
        network = Network(nodes, edges)

        # initialize simulation engine
        engine = SimulationEngine(
            network,
            defense_mode=defense_mode,
            intensity="medium"
        )

        # set attack type
        engine.current_attack = scenario["attack"]

        # run simulation
        # number of ticks scales with network size
        engine.run(
            steps=network_size,
            scenario_fn=scenario["fn"],
            db=db,
            soc_enabled=False
        )

        # get final network metrics
        final = engine.history[-1]

        # calculate infection peak
        peak_infection = max(
            h["infected"] for h in engine.history
        )

        # determine outcome
        if final["infected"] == 0:
            outcome = "Threat Eliminated"

        elif final["infected"] < peak_infection:
            outcome = "Contained"

        else:
            outcome = "Critical Spread"

        # generate infection curve chart
        infected_curve = [
            h["infected"]
            for h in engine.history
        ]

        ticks = list(range(len(infected_curve)))

        plt.figure(figsize=(8, 4))

        plt.plot(ticks, infected_curve)

        plt.xlabel("Tick")

        plt.ylabel("Infected Nodes")

        plt.title("Infection Spread Over Time")

        plt.tight_layout()

        # save chart
        plt.savefig("static/infection_curve.png")

        plt.close()

        # generate risk curve chart
        risk_curve = [
            h["risk"]
            for h in engine.history
        ]

        plt.figure(figsize=(8, 4))

        plt.plot(ticks, risk_curve)

        plt.xlabel("Tick")

        plt.ylabel("Risk Score")

        plt.title("Network Risk Evolution")

        plt.tight_layout()

        # save chart
        plt.savefig("static/risk_curve.png")

        plt.close()

        # prepare results for web page
        result = {

            # simulation overview
            "attack": engine.current_attack.upper(),
            "nodes": network_size,
            "ticks": network_size,
            "peak": peak_infection,
            "outcome": outcome,

            # final network state
            "infected": final["infected"],
            "quarantined": final["quarantined"],
            "patched": final["patched"],
            "clean": final["clean"],
            "risk": round(final["risk"], 2),

            # ai scoring
            "score": engine.scorer.score,
            "grade": engine.scorer.grade,

            # detection metrics
            "metrics": engine.detection_stats
        }

        # close database connection
        db.close()

    # render html page
    return render_template(
        "index.html",
        result=result,
        selected_scenario=request.form.get("scenario", "baseline"),
        selected_defense=request.form.get("defense", "none"),
        selected_network_size=request.form.get("network_size", 50)
    )

# run flask app locally
if __name__ == "__main__":
    app.run(debug=True)