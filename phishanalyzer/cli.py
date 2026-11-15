from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .analyzer import analyze_message


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishanalyzer", description="Analisa um e-mail .eml e aponta sinais de phishing.")
    p.add_argument("arquivos", nargs="+", help="um ou mais arquivos .eml")
    p.add_argument("--json", action="store_true", help="imprime o resultado em JSON")
    return p


def meter(score: int) -> str:
    filled = round(score / 10)
    return "■" * filled + "□" * (10 - filled)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    worst = 0
    for path in args.arquivos:
        rep = analyze_message(Path(path).read_bytes())
        worst = max(worst, rep.score)
        if args.json:
            data = asdict(rep) | {"score": rep.score, "veredito": rep.verdict}
            print(json.dumps(data, ensure_ascii=False, indent=2))
            continue
        print(f"\n  arquivo   {path}")
        print(f"  assunto   {rep.subject}")
        print(f"  de        {rep.sender}")
        if rep.reply_to:
            print(f"  responder {rep.reply_to}")
        print("  auth      " + "  ".join(f"{k.upper()} {v}" for k, v in rep.auth.items()))
        print(f"\n  risco     {meter(rep.score)} {rep.score}/100, {rep.verdict}\n")
        for s in sorted(rep.signals, key=lambda s: -s.weight):
            print(f"   +{s.weight:<3} {s.title}")
            print(f"        {s.detail}")
        if rep.links:
            print("\n  links encontrados (não clique)")
            for url in rep.links:
                print(f"   {url.replace('http', 'hxxp', 1)}")
        if rep.attachments:
            print("\n  anexos  " + ", ".join(rep.attachments))
        print()
    return 1 if worst >= 60 else 0
