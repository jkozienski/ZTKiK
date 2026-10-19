#!/usr/bin/env python3
"""
ZTKiK Lab 2 | Eksperyment 1
Czas generowania kluczy dla rosnacej liczby uzytkownikow (N kluczy).

Przebieg (zgodnie z trescia zadania):
  1. Pilotaz: dla kazdej konfiguracji serie N = 1, 4, 8, 16, ... (podwajanie),
     pomiar lacznego czasu T(N), az seria trwa >= PILOT_STOP_S sekund.
  2. Dobor Nmin (T ~ 0,2 s) i Nmax (T ~ 5-10 s) osobno dla kazdej konfiguracji,
     na podstawie sredniego czasu na klucz z pilotazu.
  3. Siatka >= 4 rosnacych wartosci N miedzy Nmin a Nmax (rozstaw geometryczny).
  4. Dla kazdego N: 5 niezaleznych serii. Kolejnosc serii (konfiguracja, N)
     jest losowana w kazdej rundzie, wiec dryf taktowania/temperatury
     nie faworyzuje zadnego algorytmu.
  5. Dla kazdego N: srednia i mediana z 5 wartosci T(N) oraz z 5 wartosci T(N)/N.
     (Bez p95: przy 5 obserwacjach percentyl nie ma sensu statystycznego.)

Mierzony jest wylacznie czas generowania kluczy: bez wypisywania, bez zapisu na
dysk, bez przechowywania kluczy (zwracana wartosc jest od razu odrzucana).

Uzycie:
    python lab2_eksperyment1.py            # pelny eksperyment
    python lab2_eksperyment1.py --quick    # szybki test dzialania skryptu (NIE do sprawozdania)
"""
import argparse
import csv
import gc
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Konfiguracje (tabela 1). Klucz = nazwa, wartosc = (algorytm, dlugosc klucza)
# ---------------------------------------------------------------------------
CONFIGS = {
    "RSA-2048": ("RSA", 2048),
    "RSA-3072": ("RSA", 3072),
    "AES-128": ("AES", 128),
    "AES-256": ("AES", 256),
    "3DES": ("3DES", 168),
}

SEED = 2026            # ziarno TYLKO dla losowania kolejnosci serii (replikowalnosc)
GRID_POINTS = 5        # ile wartosci N w siatce (musi byc >= 4)
MIN_GRID_VALUES = 4    # minimalna liczba roznych N wymagana w zadaniu
PILOT_STOP_S = 1.0     # pilotaz konczy sie, gdy seria trwa co najmniej tyle sekund
WARMUP_OPS = {"RSA": 1, "AES": 2000, "3DES": 2000}


# ---------------------------------------------------------------------------
# Generatory kluczy (jedna operacja = jeden klucz lub para kluczy RSA)
# ---------------------------------------------------------------------------
def make_generator(algo, bits):
    if algo == "RSA":
        def gen():
            return rsa.generate_private_key(public_exponent=65537, key_size=bits)
    elif algo == "AES":
        def gen():
            return AESGCM.generate_key(bit_length=bits)
    else:  # 3DES: 3 niezalezne klucze DES = 24 B (168 b materialu kluczowego)
        def gen():
            while True:
                k = os.urandom(24)
                if k[:8] != k[8:16] and k[8:16] != k[16:] and k[:8] != k[16:]:
                    return k
    return gen


# ---------------------------------------------------------------------------
# Pomiar
# ---------------------------------------------------------------------------
def run_series(gen, n):
    """Laczny czas T(N) wygenerowania N kluczy [s]. GC wylaczony na czas serii."""
    gc.collect()
    gc.disable()
    try:
        t0 = time.perf_counter_ns()
        for _ in range(n):
            gen()
        t1 = time.perf_counter_ns()
    finally:
        gc.enable()
    return (t1 - t0) / 1e9


def warmup(gen, algo):
    for _ in range(WARMUP_OPS[algo]):
        gen()


# ---------------------------------------------------------------------------
# Pilotaz i dobor N
# ---------------------------------------------------------------------------
def pilot(gen, algo, stop_s):
    """Serie N = 1, 4, 8, 16, ... az T(N) >= stop_s. Zwraca liste (N, T)."""
    warmup(gen, algo)
    rows = []
    n = 1
    while True:
        t = run_series(gen, n)
        rows.append((n, t))
        if t >= stop_s or n >= 10**9:
            return rows
        n = 4 if n == 1 else n * 2


def choose_n(pilot_rows, target_min_s, target_max_s):
    """Nmin i Nmax z lacznego sredniego czasu na klucz w pilotazu (suma T / suma N)."""
    rate = sum(t for _, t in pilot_rows) / sum(n for n, _ in pilot_rows)
    n_min = max(1, round(target_min_s / rate))
    n_max = round(target_max_s / rate)
    note = ""
    if n_max < MIN_GRID_VALUES:
        # kosztowna konfiguracja: potrzebujemy >= 4 roznych N, wiec Nmax > czas docelowy
        n_max = MIN_GRID_VALUES
        note = (f"Nmax podniesione do {MIN_GRID_VALUES}: przy {rate:.3f} s/klucz "
                f"wymagane 4 rozne N daje T(Nmax) ~ {rate * MIN_GRID_VALUES:.1f} s "
                f"(powyzej celu {target_max_s} s)")
    if n_min >= n_max:
        n_min = 1
    return rate, n_min, n_max, note


def make_grid(n_min, n_max, k=GRID_POINTS):
    vals = sorted({round(n_min * (n_max / n_min) ** (i / (k - 1))) for i in range(k)})
    if len(vals) < MIN_GRID_VALUES:
        vals = sorted(set(vals) | set(range(1, MIN_GRID_VALUES + 1)))
    return vals


# ---------------------------------------------------------------------------
# Statystyki i wyjscie
# ---------------------------------------------------------------------------
def summarize(raw):
    groups = {}
    for r in raw:
        groups.setdefault((r["config"], r["N"]), []).append(r)
    out = []
    for (cfg, n), rows in groups.items():
        T = [r["T_s"] for r in rows]
        tpk = [r["t_per_key_s"] for r in rows]
        out.append({
            "config": cfg, "N": n, "n_obs": len(rows),
            "T_mean_s": statistics.mean(T), "T_median_s": statistics.median(T),
            "tpk_mean_s": statistics.mean(tpk), "tpk_median_s": statistics.median(tpk),
        })
    order = list(CONFIGS)
    out.sort(key=lambda r: (order.index(r["config"]), r["N"]))
    return out


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def fmt_time(s):
    if s >= 1:
        return f"{s:8.3f} s "
    if s >= 1e-3:
        return f"{s * 1e3:8.3f} ms"
    return f"{s * 1e6:8.3f} us"


def print_summary(summary):
    print(f"\n{'Konfig':<9}{'N':>10}{'n':>3}  {'T mean':>11}{'T median':>12}"
          f"{'t/klucz mean':>15}{'t/klucz med':>14}")
    prev = None
    for r in summary:
        if prev and r["config"] != prev:
            print()
        prev = r["config"]
        print(f"{r['config']:<9}{r['N']:>10}{r['n_obs']:>3}  {fmt_time(r['T_mean_s']):>11}"
              f"{fmt_time(r['T_median_s']):>12}{fmt_time(r['tpk_mean_s']):>15}"
              f"{fmt_time(r['tpk_median_s']):>14}")


# ---------------------------------------------------------------------------
# Wykresy (matplotlib opcjonalny)
# ---------------------------------------------------------------------------
def make_plots(raw, summary, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n[!] Brak matplotlib: pomijam wykresy (pip install matplotlib).")
        return

    panels = [("RSA", ["RSA-2048", "RSA-3072"], 1e3, "ms"),
              ("AES / 3DES", ["AES-128", "AES-256", "3DES"], 1e6, "\u00b5s")]
    colors = {"RSA-2048": "tab:blue", "RSA-3072": "tab:red", "AES-128": "tab:green",
              "AES-256": "tab:orange", "3DES": "tab:purple"}

    def one_figure(kind):
        fig, axes = plt.subplots(1, 2, figsize=(13, 5))
        for ax, (title, cfgs, scale, unit) in zip(axes, panels):
            for cfg in cfgs:
                rows = [s for s in summary if s["config"] == cfg]
                ns = [s["N"] for s in rows]
                pts = [r for r in raw if r["config"] == cfg]
                if kind == "T":
                    f, mean_k, med_k, mult, yl = "T_s", "T_mean_s", "T_median_s", 1.0, "s"
                else:
                    f, mean_k, med_k, mult, yl = "t_per_key_s", "tpk_mean_s", "tpk_median_s", scale, unit
                ax.scatter([r["N"] for r in pts], [r[f] * mult for r in pts],
                           s=12, alpha=0.35, color=colors[cfg])
                ax.plot(ns, [s[mean_k] * mult for s in rows], "o-", color=colors[cfg],
                        label=f"{cfg} \u015brednia")
                ax.plot(ns, [s[med_k] * mult for s in rows], "s--", color=colors[cfg],
                        mfc="none", label=f"{cfg} mediana")
            ax.set_xscale("log")
            if kind == "T":
                ax.set_yscale("log")
            else:  # T(N)/N ~ const: skala liniowa od zera pokazuje faktyczny rozrzut
                ax.set_ylim(bottom=0)
            ax.set_xlabel("Liczba kluczy N")
            ax.set_ylabel("T(N) [s]" if kind == "T" else f"T(N)/N [{unit}]")
            ax.set_title(title)
            ax.grid(True, which="both", alpha=0.3)
            ax.legend(fontsize=8)
        fig.suptitle("\u0141\u0105czny czas generowania kluczy T(N)" if kind == "T"
                     else "\u015aredni czas generowania jednego klucza T(N)/N")
        fig.tight_layout()
        path = outdir / ("exp1_T_od_N.png" if kind == "T" else "exp1_T_na_klucz_od_N.png")
        fig.savefig(path, dpi=150)
        plt.close(fig)
        return path

    for kind in ("T", "tpk"):
        print("Zapisano wykres:", one_figure(kind))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5, help="serie na kazde N (min. 5)")
    ap.add_argument("--target-min", type=float, default=0.2, help="cel T(Nmin) [s]")
    ap.add_argument("--target-max", type=float, default=7.5, help="cel T(Nmax) [s], 5-10 s")
    ap.add_argument("--quick", action="store_true",
                    help="skrocone cele czasowe, tylko test skryptu (nie do sprawozdania)")
    ap.add_argument("--out", default=None, help="katalog wynikow")
    args = ap.parse_args()
    if args.quick:
        args.target_min, args.target_max = 0.02, 0.3
        pilot_stop = 0.1
    else:
        pilot_stop = PILOT_STOP_S
        if args.reps < 5:
            sys.exit("Zadanie wymaga co najmniej 5 serii na kazde N.")

    outdir = Path(args.out) if args.out else Path(__file__).resolve().parent / "wyniki_eksp1"
    outdir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("ZTKiK Lab 2 | Eksperyment 1: czas generowania kluczy")
    print("=" * 70)
    print(f"Python {platform.python_version()}, cryptography {cryptography.__version__}, "
          f"{platform.system()} {platform.release()}")
    if args.quick:
        print("[TRYB QUICK] wyniki tylko do testu skryptu")

    # --- 1-3. Pilotaz, Nmin/Nmax, siatka -----------------------------------
    gens = {name: make_generator(*spec) for name, spec in CONFIGS.items()}
    pilot_rows, plan = [], {}
    print("\n[1] Pilotaz (N = 1, 4, 8, 16, ... do T >= %.1f s)" % pilot_stop)
    for name, (algo, _) in CONFIGS.items():
        rows = pilot(gens[name], algo, pilot_stop)
        rate, n_min, n_max, note = choose_n(rows, args.target_min, args.target_max)
        grid = make_grid(n_min, n_max)
        plan[name] = {"pilot": rows, "rate_s_per_key": rate, "N_min": n_min,
                      "N_max": n_max, "grid": grid, "note": note}
        for n, t in rows:
            pilot_rows.append({"config": name, "N": n, "T_s": t, "t_per_key_s": t / n})
        print(f"  {name:<9} {len(rows)} serii pilotazu, ~{fmt_time(rate).strip()}/klucz "
              f"-> Nmin={n_min}, Nmax={n_max}, siatka={grid}")
        if note:
            print(f"            UWAGA: {note}")
    write_csv(outdir / "exp1_pilot.csv", pilot_rows, ["config", "N", "T_s", "t_per_key_s"])

    # --- 4. Serie pomiarowe w losowej kolejnosci ---------------------------
    tasks = [(name, n) for name in CONFIGS for n in plan[name]["grid"]]
    rng = random.Random(SEED)
    raw = []
    print(f"\n[2] Pomiary: {args.reps} rund x {len(tasks)} serii (kolejnosc losowana, seed={SEED})")
    for rep in range(1, args.reps + 1):
        order = tasks[:]
        rng.shuffle(order)
        for pos, (name, n) in enumerate(order, 1):
            algo = CONFIGS[name][0]
            warmup(gens[name], algo)
            t = run_series(gens[name], n)
            raw.append({"repetition": rep, "run_order": pos, "config": name, "N": n,
                        "T_s": t, "t_per_key_s": t / n})
            print(f"  runda {rep}/{args.reps} [{pos:>2}/{len(order)}] {name:<9} N={n:<9} "
                  f"T={fmt_time(t).strip()}", flush=True)

    # --- 5. Statystyki ------------------------------------------------------
    summary = summarize(raw)
    write_csv(outdir / "exp1_surowe.csv", raw,
              ["repetition", "run_order", "config", "N", "T_s", "t_per_key_s"])
    write_csv(outdir / "exp1_podsumowanie.csv", summary,
              ["config", "N", "n_obs", "T_mean_s", "T_median_s", "tpk_mean_s", "tpk_median_s"])
    meta = {
        "python": platform.python_version(), "cryptography": cryptography.__version__,
        "system": f"{platform.system()} {platform.release()} {platform.version()}",
        "machine": platform.machine(), "cpu_count": os.cpu_count(),
        "seed_kolejnosci": SEED, "reps": args.reps,
        "target_min_s": args.target_min, "target_max_s": args.target_max,
        "pilot_stop_s": pilot_stop, "quick": args.quick,
        "plan": {k: {kk: vv for kk, vv in v.items() if kk != "pilot"} for k, v in plan.items()},
    }
    (outdir / "exp1_parametry.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                                                encoding="utf-8")

    print_summary(summary)
    print("\nPliki wynikowe w:", outdir)
    make_plots(raw, summary, outdir)


if __name__ == "__main__":
    main()