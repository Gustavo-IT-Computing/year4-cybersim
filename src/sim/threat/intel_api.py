import requests
import os
import random

# API key used for external threat intelligence lookups
API_KEY = os.getenv("VT_API_KEY")

# check an indicator using VirusTotal or fallback intelligence
def check_with_api(indicator: str) -> dict:

    # build request URL
    url = (
        f"https://www.virustotal.com/"
        f"api/v3/files/{indicator}"
    )

    headers = {
        "x-apikey": API_KEY
    }

    # no API key → simulated intelligence
    if not API_KEY:

        print(
            "[API] No API key → "
            "using simulated intelligence"
        )

        return simulate_api_response()

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=5
        )

        print(
            f"[API] Status Code: "
            f"{response.status_code}"
        )

        # valid response
        if response.status_code == 200:

            print(
                "[API] Connected to VirusTotal"
            )

            data = response.json()

            stats = data["data"]["attributes"][
                "last_analysis_stats"
            ]

            print(f"[API] Stats: {stats}")

            # malicious detected
            if stats.get("malicious", 0) > 0:

                return {
                    "verdict": "malicious",
                    "confidence": stats["malicious"]
                }

            # otherwise harmless
            return {
                "verdict": "harmless",
                "confidence": stats.get(
                    "harmless",
                    0
                )
            }

        # indicator not found
        elif response.status_code == 404:

            print(
                "[API] Indicator not found "
                "→ fallback intelligence"
            )

            return simulate_api_response()

        # rate limit exceeded
        elif response.status_code == 429:

            print(
                "[API] Rate limit exceeded "
                "→ fallback"
            )

            return simulate_api_response()

        # invalid key
        elif response.status_code == 401:

            print(
                "[API] Invalid API key "
                "→ fallback"
            )

            return simulate_api_response()

        # unexpected response
        else:

            print(
                f"[API] Unexpected response: "
                f"{response.status_code}"
            )

            return simulate_api_response()

    # request failed
    except Exception as error:

        print(
            f"[API] Request failed: "
            f"{error}"
        )

        return simulate_api_response()

# simulate intelligence when API unavailable
def simulate_api_response() -> dict:

    roll = random.random()

    # clearly malicious
    if roll < 0.25:

        return {
            "verdict": "malicious",
            "confidence": random.randint(
                20,
                80
            )
        }

    # most often unknown
    elif roll < 0.75:

        return {
            "verdict": "unknown",
            "confidence": 0
        }

    # sometimes harmless
    return {
        "verdict": "harmless",
        "confidence": random.randint(
            0,
            20
        )
    }