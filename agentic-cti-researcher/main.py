import argparse

from src.sources.mitre import (
    get_attack_data,
    find_actor,
    get_attack_id,
    get_actor_techniques,
)

from src.sources.otx import (
    search_and_normalize,
)


def main():

    parser = argparse.ArgumentParser(
        description="Agentic CTI Researcher"
    )

    parser.add_argument(
        "--actor",
        required=True,
        help="Threat actor name",
    )

    args = parser.parse_args()

    # --------------------------------------------------
    # MITRE ATT&CK
    # --------------------------------------------------

    print("Loading MITRE ATT&CK data...")

    data = get_attack_data()

    print(
        f"Searching MITRE for: {args.actor}"
    )

    actor = find_actor(
        data,
        args.actor,
    )

    if not actor:

        print(
            f"Actor not found in MITRE: "
            f"{args.actor}"
        )

        return

    actor_id = get_attack_id(actor)

    techniques = get_actor_techniques(
        data,
        actor.get("id"),
    )

    print("\n" + "=" * 60)
    print("MITRE ATT&CK")
    print("=" * 60)

    print(
        f"Name: {actor.get('name', 'Unknown')}"
    )

    print(
        f"ATT&CK ID: "
        f"{actor_id or 'Unknown'}"
    )

    aliases = actor.get("aliases", [])

    if aliases:

        print(
            f"Aliases: "
            f"{', '.join(aliases)}"
        )

    print(
        f"Techniques found: "
        f"{len(techniques)}"
    )

    for technique in techniques:

        print(
            f"- {technique['id']}: "
            f"{technique['name']}"
        )

    # --------------------------------------------------
    # AlienVault OTX
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("ALIENVAULT OTX")
    print("=" * 60)

    print(
        f"Searching OTX for: "
        f"{args.actor}"
    )

    try:

        pulses = search_and_normalize(
            args.actor
        )

        print(
            f"OTX pulses found: "
            f"{len(pulses)}"
        )

        for pulse in pulses:

            print(
                f"\n- {pulse.get('name')}"
            )

            print(
                f"  ID: "
                f"{pulse.get('id')}"
            )

            if pulse.get("description"):

                description = (
                    pulse["description"]
                )

                print(
                    f"  Description: "
                    f"{description[:300]}"
                )

            if pulse.get("tags"):

                print(
                    f"  Tags: "
                    f"{', '.join(pulse['tags'])}"
                )

    except Exception as error:

        print(
            f"OTX research failed: "
            f"{error}"
        )


if __name__ == "__main__":
    main()
