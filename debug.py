"""Deep Diagnostic and Debug Tool for SafeSMS-KE.

Dissects model classification, text normalisation, regex lexicon matches,
URL security heuristics, and linear feature attribution for any SMS.

Usage:
    python debug.py "message text"
    python debug.py --file message.txt
    python debug.py --json "message text"
"""
import json
import sys
from pathlib import Path

from safesms import (
    BAD_TLDS,
    BRANDS,
    DENSE,
    LABELS,
    OFFICIAL,
    SHORTENERS,
    URL_LABELS,
    W,
    load,
    normalize,
    url_features,
    url_report,
)

USE_COLOR = sys.stdout.isatty()


def colorize(t, c):
    return f"\033[{c}m{t}\033[0m" if USE_COLOR else t


def red(t): return colorize(t, "91;1")
def green(t): return colorize(t, "92;1")
def yellow(t): return colorize(t, "93;1")
def cyan(t): return colorize(t, "96;1")
def bold(t): return colorize(t, "1")
def dim(t): return colorize(t, "90")


def print_section(title):
    print("\n" + bold(f"[{title}]"))
    print("-" * 70)


def debug_message(text, json_output=False):
    model = load()
    dbg = model.explain_debug(text)

    if json_output:
        print(json.dumps(dbg, indent=2))
        return

    print("=" * 70)
    print(bold("                  SafeSMS-KE Diagnostic Inspector                  "))
    print("=" * 70)

    # 1. Raw Input
    print_section("1. INPUT MESSAGE DETAILS")
    print(f"Text:        \"{text}\"")
    print(f"Length:      {len(text)} characters ({len(text.split())} words)")
    letters = [c for c in text if c.isalpha()]
    caps_ratio = sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
    print(f"Uppercase:   {caps_ratio:.1%} | Exclamation marks: {text.count('!')}")

    # 2. Normalisation
    print_section("2. NORMALISATION & TOKEN MASKING")
    print(f"Normalized:  \"{dbg['normalized']}\"")
    print(dim("Masking replaces variable entities (URLs, phones, money amounts, codes)"))
    print(dim("with abstract tokens so the model generalises on wording patterns."))

    # 3. Decision & Verdict
    print_section("3. MODEL VERDICT & DECISION FLOW")
    v = dbg["verdict"]
    v_badge = red("SCAM") if v == "SCAM" else (yellow("SUSPICIOUS") if v == "SUSPICIOUS" else green("SAFE"))
    print(f"Verdict:              {bold(v_badge)}")
    print(f"Scam Probability:     {bold(str(dbg['score']))} ({dbg['score'] * 100:.1f}%)")
    print(f"Raw Linear Margin:    {dbg['raw_margin']:+.4f} (log-odds)")

    # Decision threshold explanation
    print("\nDecision Thresholds:")
    print("  • Score >= 0.70  -> SCAM")
    print("  • Score 0.40-0.70-> SUSPICIOUS")
    print("  • Score < 0.40   -> SAFE")
    if dbg["escalated"]:
        print(yellow("  • ESCALATION TRIGGERED: Safe message lifted to SUSPICIOUS due to risky link (risk >= 0.70)."))
    else:
        print(dim("  • Link escalation rule: Inactive"))

    # 4. User-Facing Explanations
    print_section("4. PRIMARY EXPLANATION REASONS (Objective O4)")
    for i, r in enumerate(dbg["reasons"], 1):
        bullet = red("•") if v == "SCAM" else (yellow("•") if v == "SUSPICIOUS" else green("•"))
        print(f"  {bullet} Reason {i}: {r}")

    # 5. URL Security Heuristics
    print_section("5. URL SECURITY HEURISTICS (Objective O3)")
    links = dbg["links"]
    if not links:
        print("  No URLs detected in this message.")
    else:
        for idx, l in enumerate(links, 1):
            url_str = l["url"]
            risk = l["risk"]
            r_col = red if risk >= 0.70 else (yellow if risk >= 0.40 else green)
            print(f"\n  Link #{idx}: {cyan(url_str)}")
            print(f"  Calculated Risk: {r_col(f'{risk:.2f}')} (Base 0.10 + weighted flag sum)")
            print("  Flags Audit (10 Security Heuristics):")
            u_feats = url_features(url_str)
            for flag_key, weight in W.items():
                fired = u_feats.get(flag_key, 0) == 1
                flag_desc = URL_LABELS.get(flag_key, flag_key)
                if fired:
                    status = red(f"[X] {flag_key:<15}")
                    print(f"    {status} (+{weight:.2f}) - {flag_desc}")
                else:
                    status = dim(f"[ ] {flag_key:<15}")
                    print(f"    {status} ( 0.00) - {flag_desc}")

    # 6. Dense Feature Activations
    print_section("6. DENSE DOMAIN & LEXICON SIGNALS")
    active_dense = dbg["dense_active"]
    if not active_dense:
        print("  No dense features triggered.")
    else:
        for feat_name, val in active_dense.items():
            label = LABELS.get(feat_name, feat_name)
            print(f"  • {feat_name:<20} = {val:.2f}  ({label})")

    # 7. Linear Log-Odds Contributions
    print_section("7. TOP LINEAR FEATURE CONTRIBUTIONS")
    top_c = dbg["top_contributions"]
    if not top_c:
        print("  No significant positive feature weights.")
    else:
        for c in top_c:
            bar_len = int(min(20, max(1, c["weight"] * 8)))
            bar = "■" * bar_len
            w_str = f"{c['weight']:>+6.3f}"
            print(f"  {c['feature']:<28} {red(w_str)} {red(bar)}")

    print("=" * 70 + "\n")


def main():
    args = sys.argv[1:]
    json_mode = "--json" in args

    clean_args = [a for a in args if a != "--json"]

    if not clean_args:
        try:
            text = input("Enter message to debug: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not text:
            print("Empty message provided.")
            return
        debug_message(text, json_output=json_mode)
        return

    if clean_args[0] == "--file" and len(clean_args) > 1:
        fpath = Path(clean_args[1])
        if not fpath.exists():
            print(f"File not found: {fpath}", file=sys.stderr)
            sys.exit(1)
        text = fpath.read_text(encoding="utf-8").strip()
        debug_message(text, json_output=json_mode)
        return

    text = " ".join(clean_args).strip()
    debug_message(text, json_output=json_mode)


if __name__ == "__main__":
    main()
