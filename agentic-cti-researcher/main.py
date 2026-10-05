
import argparse

from src.sources.mitre import (
    get_attack_data,
    find_actor,
    get_attack_id,
    get_actor_techniques,
)


def main():
    parser = argparse.ArgumentParser(
        description="Agentic CTI Researcher"
    )

    parser.add_argument(
        "--actor",
        required=True,
        help="Threat actor name, for example APT28",
    )

    args = parser.parse_args()

    print("Loading MITRE ATT&CK data...")

    data = get_attack_data()

    print(f"Searching for actor: {args.actor}")

    actor = find_actor(data, args.actor)

    if not actor:
        print(f"Actor not found: {args.actor}")
        return

    actor_id = get_attack_id(actor)

    techniques = get_actor_techniques(
        data,
        actor.get("id"),
    )

    print("\n" + "=" * 60)
    print("THREAT ACTOR")
    print("=" * 60)

    print(f"Name: {actor.get('name', 'Unknown')}")
    print(f"ATT&CK ID: {actor_id or 'Unknown'}")

    aliases = actor.get("aliases", [])

    if aliases:
        print(f"Aliases: {', '.join(aliases)}")

    description = actor.get("description")

    if description:
        print(f"\nDescription:\n{description}")

    print("\n" + "=" * 60)
    print(f"MITRE ATT&CK TECHNIQUES ({len(techniques)})")
    print("=" * 60)

    for technique in techniques:
        print(
            f"- {technique['id']}: "
            f"{technique['name']}"
        )


if __name__ == "__main__":
    main()
