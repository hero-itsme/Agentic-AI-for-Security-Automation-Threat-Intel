import requests

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def get_attack_data():
    """Download the MITRE ATT&CK Enterprise STIX dataset."""
    response = requests.get(MITRE_ATTACK_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def find_actor(data, actor_name):
    """Find a threat actor/intrusion-set by name or alias."""
    query = actor_name.strip().casefold()

    for obj in data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue

        names = [obj.get("name", "")]
        names.extend(obj.get("aliases", []))

        if any(query == str(name).casefold() for name in names):
            return obj

    return None


def get_attack_id(obj):
    """Extract the MITRE ATT&CK external ID."""
    for reference in obj.get("external_references", []):
        if (
            reference.get("source_name") == "mitre-attack"
            and reference.get("external_id")
        ):
            return reference["external_id"]

    return None


def get_actor_techniques(data, actor_id):
    """Find MITRE ATT&CK techniques used by the actor."""

    objects = {
        obj.get("id"): obj
        for obj in data.get("objects", [])
        if obj.get("id")
    }

    techniques = []

    for relationship in data.get("objects", []):
        if relationship.get("type") != "relationship":
            continue

        if relationship.get("relationship_type") != "uses":
            continue

        if relationship.get("source_ref") != actor_id:
            continue

        target = objects.get(relationship.get("target_ref"))

        if not target:
            continue

        if target.get("type") != "attack-pattern":
            continue

        technique_id = get_attack_id(target)

        if technique_id:
            techniques.append(
                {
                    "id": technique_id,
                    "name": target.get("name", ""),
                }
            )

    return sorted(
        techniques,
        key=lambda technique: technique["id"]
    )
