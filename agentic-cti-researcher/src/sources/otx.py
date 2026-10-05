import os
import requests


OTX_BASE_URL = "https://otx.alienvault.com/api/v1"


def get_api_key():
    """Get the OTX API key from the environment."""

    api_key = os.getenv("OTX_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OTX_API_KEY is not configured."
        )

    return api_key


def search_actor(actor_name):
    """
    Search AlienVault OTX for threat-intelligence
    information related to a threat actor.
    """

    api_key = get_api_key()

    url = f"{OTX_BASE_URL}/search/pulses"

    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
    }

    params = {
        "q": actor_name,
        "page": 1,
        "limit": 10,
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=30,
    )

    response.raise_for_status()

    return response.json()


def normalize_pulses(data):
    """
    Convert raw OTX pulse results into a simpler
    structure for our CTI pipeline.
    """

    normalized = []

    for pulse in data.get("results", []):

        normalized.append(
            {
                "id": pulse.get("id"),
                "name": pulse.get("name"),
                "description": pulse.get(
                    "description"
                ),
                "created": pulse.get("created"),
                "modified": pulse.get("modified"),
                "author": pulse.get(
                    "author_name"
                ),
                "tlp": pulse.get("tlp"),
                "tags": pulse.get(
                    "tags", []
                ),
                "references": pulse.get(
                    "references", []
                ),
            }
        )

    return normalized


def search_and_normalize(actor_name):
    """
    Search OTX and return normalized pulse data.
    """

    raw_data = search_actor(actor_name)

    return normalize_pulses(raw_data)
