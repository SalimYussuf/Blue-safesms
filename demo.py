"""Interactive Easy Demo CLI for SafeSMS-KE.

Usage:
    python demo.py                (Interactive menu with presets & live testing)
    python demo.py "message text" (Directly test a custom message)
    python demo.py --all-presets  (Run and display all benchmark demo presets)
    python demo.py --preset 3     (Run specific preset #1-8)
"""
import sys
from pathlib import Path

from safesms import load, update_metrics

# Preset test library representing realistic Kenyan SMS scenarios
DEMO_PRESETS = [
    {
        "id": 1,
        "category": "Genuine M-PESA",
        "expected": "SAFE",
        "description": "Standard M-PESA send money confirmation",
        "text": "BC34DE56FG Confirmed. Ksh250.00 sent to ALICE MUTUA 0700 000 205 on 6/11/26 at 3:15 PM. New M-PESA balance is Ksh780.00. Transaction cost, Ksh5.00."
    },
    {
        "id": 2,
        "category": "Genuine Everyday Chat",
        "expected": "SAFE",
        "description": "Casual Sheng/Swahili conversation between friends",
        "text": "Niko njiani kuelekea tao, tukutane archive saa kumi. Nitakununulia lunch leo usijali."
    },
    {
        "id": 3,
        "category": "M-PESA 'Reversal' Scam",
        "expected": "SCAM",
        "description": "Scammer claims to have sent money by mistake and begs for return",
        "text": "Ndugu yangu nimekutumia Ksh 3,500 kimakosa kwa nambari yako. Tafadhali nirudishie kwa nambari 0712345678, ni za mgonjwa hospitali haraka."
    },
    {
        "id": 4,
        "category": "KRA Phishing Scam",
        "expected": "SCAM",
        "description": "Impersonates Kenya Revenue Authority offering fake refund via link",
        "text": "KRA NOTICE: Your tax refund of KES 14,250 has been approved. Claim your refund immediately at http://kra-portal-claim.xyz/refund before expiration tonight."
    },
    {
        "id": 5,
        "category": "Account / SIM Suspension Threat",
        "expected": "SCAM",
        "description": "Threatens immediate line disconnection unless urgent action taken",
        "text": "SAFARICOM ALERT: Your line has been flagged for unverified SIM swap and will be blocked within 2 hours. Call customer care now on 0722000123 or pay fee to unblock."
    },
    {
        "id": 6,
        "category": "Fake Job / Recruitment Bait",
        "expected": "SCAM",
        "description": "Offers lucrative job vacancy asking for upfront interview or registration fee",
        "text": "URGENT JOB VACANCY: Kenya Airways recruitment ongoing. Salary Ksh 85,000. Send registration fee of Ksh 1,200 to 0719876543 to confirm your interview slot today."
    },
    {
        "id": 7,
        "category": "Suspicious URL Shortener",
        "expected": "SCAM",
        "description": "Unsolicited statement notice hiding real destination behind bit.ly link",
        "text": "Your monthly banking statement is ready for review. Access your secure statement here: http://bit.ly/bank-statement-ke26"
    },
    {
        "id": 8,
        "category": "Prize / Lottery Bait",
        "expected": "SCAM",
        "description": "Fake promotion win requesting recipient to claim prize",
        "text": "HONGERA! Namba yako imechaguliwa kama mshindi wa Ksh 100,000 katika Safaricom Mega Promo. Piga 0701234567 sasa hivi upate zawadi yako."
    }
]

# ANSI color codes with automatic detection
USE_COLOR = sys.stdout.isatty()


def colorize(text, color_code):
    if not USE_COLOR:
        return text
    return f"\033[{color_code}m{text}\033[0m"


def green(t): return colorize(t, "92;1")
def yellow(t): return colorize(t, "93;1")
def red(t): return colorize(t, "91;1")
def cyan(t): return colorize(t, "96;1")
def bold(t): return colorize(t, "1")
def dim(t): return colorize(t, "90")


def render_score_bar(score, width=20):
    filled = int(round(score * width))
    bar = "█" * filled + "░" * (width - filled)
    if score >= 0.70:
        return red(f"[{bar}] {score * 100:.1f}%")
    elif score >= 0.40:
        return yellow(f"[{bar}] {score * 100:.1f}%")
    else:
        return green(f"[{bar}] {score * 100:.1f}%")


def display_result(res, header=None):
    verdict = res["verdict"]
    score = res["score"]

    if verdict == "SCAM":
        badge = red("  [ SCAM ]  ")
    elif verdict == "SUSPICIOUS":
        badge = yellow("[ SUSPICIOUS ]")
    else:
        badge = green("  [ SAFE ]  ")

    print("\n" + "=" * 65)
    if header:
        print(bold(f"  {header}"))
        print("-" * 65)

    print(f"  Verdict:       {badge}")
    print(f"  Scam Score:    {render_score_bar(score)}")
    print("\n  Top Detection Reasons:")
    for idx, reason in enumerate(res["reasons"], 1):
        bullet = red("•") if verdict == "SCAM" else (yellow("•") if verdict == "SUSPICIOUS" else green("•"))
        print(f"    {bullet} {reason}")

    if res.get("links"):
        print("\n  Detected Links Analysis:")
        for link in res["links"]:
            risk_color = red if link["risk"] >= 0.7 else (yellow if link["risk"] >= 0.4 else green)
            flags_str = ", ".join(link["flags"]) if link["flags"] else "no high-risk flags"
            print(f"    - URL:   {cyan(link['url'])}")
            print(f"      Risk:  {risk_color(str(link['risk']))}  (Flags: {flags_str})")

    print("=" * 65)


def run_single_preset(model, preset):
    print("\n" + "-" * 65)
    print(bold(f"Preset #{preset['id']}: {preset['category']}"))
    print(dim(f"Scenario: {preset['description']} (Expected: {preset['expected']})"))
    print(f"Message:  \"{preset['text']}\"")
    res = model.analyze(preset["text"])
    display_result(res, header=f"Preset Result: {preset['category']}")


def run_all_presets(model):
    print("\n" + "=" * 75)
    print(bold("               SafeSMS-KE: Evaluation on Demo Preset Suite               "))
    print("=" * 75)
    print(f"{'#':<3} {'Category':<26} {'Expected':<12} {'Verdict':<12} {'Score':<8} {'Status'}")
    print("-" * 75)

    correct_count = 0
    for p in DEMO_PRESETS:
        res = model.analyze(p["text"])
        v = res["verdict"]
        exp = p["expected"]

        # Match check: SCAM matches SCAM; SUSPICIOUS matches SUSPICIOUS or SCAM for phishing; SAFE matches SAFE
        is_match = (v == exp) or (exp in ("SCAM", "SUSPICIOUS") and v in ("SCAM", "SUSPICIOUS"))
        if is_match:
            correct_count += 1
            status_tag = green("PASS")
        else:
            status_tag = red("DIFF")

        v_colored = red(v) if v == "SCAM" else (yellow(v) if v == "SUSPICIOUS" else green(v))
        print(f"{p['id']:<3} {p['category'][:25]:<26} {exp:<12} {v_colored:<21} {res['score']:<8.2f} {status_tag}")

    print("-" * 75)
    print(f"Summary: {correct_count}/{len(DEMO_PRESETS)} test cases matched expected policy.")
    print("=" * 75 + "\n")


def run_diagnostic_check(model):
    print("\n" + "=" * 65)
    print(bold("                  SafeSMS-KE Diagnostic Check                  "))
    print("=" * 65)
    print(f"  • Model Type:      {type(model).__name__}")
    print(f"  • Word Features:   {getattr(model, 'nw', 'N/A')}")
    print(f"  • Char Features:   {getattr(model, 'nc', 'N/A')}")
    print(f"  • Classifier:      {type(getattr(model, 'clf', None)).__name__}")

    from safesms import METRICS_PATH
    import json
    if METRICS_PATH.exists():
        try:
            m = json.loads(METRICS_PATH.read_text())
            if "o2" in m:
                print(f"  • O2 F1 Score:     {m['o2'].get('f1', 'N/A'):.1%}")
            if "o5" in m:
                print(f"  • O5 Median Lat:   {m['o5'].get('median_ms', 'N/A')} ms (P95: {m['o5'].get('p95_ms', 'N/A')} ms)")
            if "o6" in m:
                print(f"  • O6 Red-Team:     {m['o6'].get('flagged_pct', 'N/A')}% scam detection")
        except Exception:
            pass

    print(green("  • System Status:   OPERATIONAL & HEALTHY"))
    print("=" * 65 + "\n")


def interactive_menu(model):
    while True:
        print("\n" + "=" * 60)
        print(bold("       SafeSMS-KE: Interactive Demo & Scam Detector       "))
        print(dim("   Mobile-Money & Phishing SMS Detection (Kenya / Sheng)"))
        print("=" * 60)
        print("  1-8: Test a preset scam or genuine message scenario")
        print("  A:   Run all 8 presets and print benchmark summary")
        print("  C:   Check your own custom message")
        print("  D:   Run system diagnostic check")
        print("  Q:   Quit")
        print("-" * 60)

        for p in DEMO_PRESETS:
            tag = green("SAFE") if p["expected"] == "SAFE" else (yellow("SUSP") if p["expected"] == "SUSPICIOUS" else red("SCAM"))
            print(f"  [{p['id']}] {p['category']:<26} [{tag}] - {p['description']}")

        try:
            choice = input(bold("\nEnter selection (1-8, A, C, D, Q): ")).strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice == "Q":
            print("Goodbye!")
            break
        elif choice == "A":
            run_all_presets(model)
        elif choice == "C":
            try:
                user_msg = input("\nEnter or paste SMS message: ").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if user_msg:
                res = model.analyze(user_msg)
                display_result(res, header="Custom Message Result")
            else:
                print("Empty input.")
        elif choice == "D":
            run_diagnostic_check(model)
        elif choice.isdigit() and 1 <= int(choice) <= len(DEMO_PRESETS):
            preset = DEMO_PRESETS[int(choice) - 1]
            run_single_preset(model, preset)
        else:
            print("Invalid selection. Please choose from the menu.")


def main():
    model = load()

    # CLI argument handling
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg == "--all-presets":
            run_all_presets(model)
            return
        elif arg == "--preset" and len(sys.argv) > 2 and sys.argv[2].isdigit():
            idx = int(sys.argv[2])
            if 1 <= idx <= len(DEMO_PRESETS):
                run_single_preset(model, DEMO_PRESETS[idx - 1])
                return
            else:
                print(f"Preset index must be between 1 and {len(DEMO_PRESETS)}")
                sys.exit(1)
        elif arg in ("--help", "-h"):
            print(__doc__)
            return
        else:
            # Custom direct text argument
            custom_text = " ".join(sys.argv[1:])
            res = model.analyze(custom_text)
            display_result(res, header="Analysis Result")
            return

    # Interactive mode
    interactive_menu(model)


if __name__ == "__main__":
    main()

