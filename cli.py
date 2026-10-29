# cli.py
"""CLI-обёртка для сканера. Импортирует логику из основного модуля."""

import argparse
import os
import sys
import nmap

# Импортируем всё нужное из основного файла.
# Замени 'scanner' на имя своего файла без .py
from scanner import (
    DIRSEARCH_PATH,
    scan_targets,
    run_dirsearch,
    run_nuclei,
    load_targets,
    targets as DEFAULT_TARGETS,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Comprehensive Security Scanner: TCP | SSL | Headers | Certs | Dirsearch | Nuclei",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python cli.py targets.txt
  python cli.py targets.txt --dirsearch
  python cli.py targets.txt --nuclei --yes
  python cli.py targets.txt --dirsearch --nuclei --ports 80,443,8080
  python cli.py example.com --dirsearch
  cat targets.txt | python cli.py - --nuclei -y
"""
    )
    parser.add_argument("targets", nargs="?",
                        help="Файл с целями или '-' для stdin. "
                             "Если не указан — используется встроенный список.")
    parser.add_argument("--dirsearch", action="store_true", help="Запустить dirsearch")
    parser.add_argument("--nuclei", action="store_true", help="Запустить nuclei")
    parser.add_argument("--ports", default="",
                        help="Порты через запятую (например 80,443,8080)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Не спрашивать подтверждения")
    parser.add_argument("--timeout", type=int, default=1800,
                        help="Таймаут на один скан, сек")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    print("=" * 60)
    print("COMPREHENSIVE SECURITY SCANNER")
    print("Scans: TCP | SSL Ciphers | Headers | Certificates | Dirsearch | Nuclei")
    print("=" * 60)

    run_ds = args.dirsearch or not (args.dirsearch or args.nuclei)
    run_nuc = args.nuclei

    # --- проверка dirsearch ---
    if run_ds and not os.path.exists(DIRSEARCH_PATH):
        print(f"⚠ Dirsearch not found at: {DIRSEARCH_PATH}")
        ans = input("Continue without dirsearch? (y/n): ").strip().lower()
        if ans not in ("y", "yes", "д", "да"):
            sys.exit(1)

    # --- загрузка целей ---
    if args.targets:
        loaded = load_targets(args.targets)
        if not loaded:
            print("❌ Нет целей")
            sys.exit(1)
    # else:
    #     loaded = DEFAULT_TARGETS
    #     if isinstance(loaded, str):
    #         loaded = [loaded]
    else:
        loaded = DEFAULT_TARGETS
        if isinstance(loaded, str):
            print(f"⚠ Цель по умолчанию: {loaded}. Файл будет передан в scan_targets.")
            # scan_targets сам откроет файл, если он существует
            if not os.path.isfile(loaded):
                print(f"❌ Файл '{loaded}' не найден. Укажи файл: python cli.py targets.txt")
                sys.exit(1)
            scan_targets(loaded)
            return

    print(f"📋 Целей: {len(loaded)}")
    for t in loaded:
        print(f"   • {t}")

    # --- порты ---
    ports = [int(p) for p in args.ports.split(",") if p.strip()] if args.ports else [None]

    # --- основной скан (TCP/SSL/Headers/Certs) ---
    if not args.dirsearch and not args.nuclei:
        # scan_targets ожидает ПУТЬ К ФАЙЛУ, а не список хостов
        if args.targets and args.targets != "-":
            scan_targets(args.targets)  # путь к файлу
        else:
            # нет файла — создадим временный из loaded
            import tempfile
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".txt", delete=False, encoding="utf-8"
            ) as tmp:
                for t in loaded:
                    tmp.write(t + "\n")
                tmp_path = tmp.name
            try:
                scan_targets(tmp_path)
            finally:
                os.remove(tmp_path)
        return

    # --- только dirsearch/nuclei ---
    for target in loaded:
        for port in ports:
            if run_ds:
                run_dirsearch(target, port, auto_confirm=args.yes)
            if run_nuc:
                run_nuclei(target, port, auto_confirm=args.yes)


if __name__ == "__main__":
    main()