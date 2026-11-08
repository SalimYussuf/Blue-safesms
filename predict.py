"""Check one message via CLI.
Usage:
    python predict.py "message text"
    python predict.py --debug "message text"
    python predict.py --json "message text"
    python predict.py   (prompts interactively)
"""
import json
import sys

from safesms import load, pretty


def main():
    args = sys.argv[1:]
    debug_mode = "--debug" in args
    json_mode = "--json" in args

    filtered_args = [a for a in args if a not in ("--debug", "--json")]

    if filtered_args:
        text = " ".join(filtered_args).strip()
    else:
        try:
            text = input("Message: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAnalysis cancelled.")
            return

    if not text:
        print("Error: Empty message provided.", file=sys.stderr)
        sys.exit(1)

    model = load()

    if debug_mode:
        dbg = model.explain_debug(text)
        if json_mode:
            print(json.dumps(dbg, indent=2))
        else:
            print(f"Verdict: {dbg['verdict']}  (scam score: {dbg['score']:.4f}, raw margin: {dbg['raw_margin']:+.3f})")
            print(f"Escalated by link risk: {dbg['escalated']}")
            print("Why:")
            for i, r in enumerate(dbg["reasons"], 1):
                print(f"  {i}. {r}")
            print(f"Normalized: {dbg['normalized']}")
            if dbg["links"]:
                print("Links:")
                for l in dbg["links"]:
                    print(f"  {l['url']}  (risk: {l['risk']:.2f}, flags: {l['flags']})")
            print("Active dense features:")
            for k, v in dbg["dense_active"].items():
                print(f"  - {k}: {v}")
            print("Top feature contributions (log-odds):")
            for c in dbg["top_contributions"]:
                print(f"  - {c['feature']}: {c['weight']:+.3f}")
    elif json_mode:
        print(json.dumps(model.analyze(text), indent=2))
    else:
        print(pretty(model.analyze(text)))


if __name__ == "__main__":
    main()
