#!/usr/bin/env python3
"""
ZTKiK Lab 2 | Eksperyment 2
Czas szyfrowania i deszyfrowania dla wiadomosci o rosnacej wielkosci
+ metryki: przepustownosc (MiB/s) i narzut danych (bajty, %).

Projekt pomiaru:
  * Dane (os.urandom) i klucze przygotowane PRZED pomiarem czasu. Te same bajty
    sa uzyte dla wszystkich konfiguracji symetrycznych o tym samym rozmiarze.
  * Nonce (AES-GCM) i IV (3DES-CBC) generowane przed pomiarem, unikalne dla kazdej
    operacji. Mierzone jest tylko szyfrowanie/deszyfrowanie (w 3DES lacznie z
    dopelnieniem PKCS#7 i utworzeniem kontekstu szyfru).
  * Rozgrzewka (odrzucana) przed kalibracja i pomiarami.
  * Operacje krotkie mierzone partiami: jeden pomiar = czas partii B operacji,
    a wynik = czas partii / B. B dobierane w kalibracji tak, by partia trwala
    okolo TARGET_BATCH_S (osobno dla szyfrowania i deszyfrowania).
  * 30 niezaleznych pomiarow szyfrowania i 30 deszyfrowania dla kazdej konfiguracji
    i rozmiaru. Pomiary w 30 rundach; w kazdej rundzie losowa kolejnosc
    (konfiguracja, rozmiar) i losowa kolejnosc szyfrowanie/deszyfrowanie.
  * Poprawnosc: po kazdym pomiarze porownanie wyniku z oryginalem bajt po bajcie
    (szyfrowanie: odszyfrowanie ostatniego szyfrogramu poza pomiarem czasu;
    deszyfrowanie: porownanie ostatniego wyniku z oryginalem). Wyjatek lub
    niezgodnosc = blad, czas takiego pomiaru NIE trafia do statystyk.
    Dodatkowo przed pomiarami weryfikowane sa wszystkie szyfrogramy wejsciowe.
  * Statystyki z 30 obserwacji: srednia, mediana, p95, odchylenie standardowe.

Uzycie:
    python lab2_eksperyment2.py            # pelny eksperyment
    python lab2_eksperyment2.py --quick    # tylko test skryptu (NIE do sprawozdania)
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
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:  # cryptography >= 43: 3DES w module "decrepit"
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

pc = time.perf_counter_ns

# ---------------------------------------------------------------------------
# Konfiguracje (tabela 1) i rozmiary wiadomosci
# ---------------------------------------------------------------------------
CONFIGS = {  # nazwa: (algorytm, dlugosc klucza w bitach)
    "RSA-2048": ("RSA", 2048),
    "RSA-3072": ("RSA", 3072),
    "AES-128-GCM": ("AES", 128),
    "AES-256-GCM": ("AES", 256),
    "3DES-CBC": ("3DES", 168),
}
SIZES_SYM = [128, 512, 2 * 1024, 8 * 1024, 32 * 1024,
             1024 ** 2, 4 * 1024 ** 2, 16 * 1024 ** 2]
SIZES_RSA = [16, 32, 64, 128, 190]

SEED = 2026               # ziarno tylko dla kolejnosci pomiarow
MIN_REPS = 30
WARMUP_OPS = 3
TARGET_BATCH_S = 2e-3     # docelowy czas jednej partii
MAX_BATCH = 20000
OAEP = asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)


# ---------------------------------------------------------------------------
# Klucze
# ---------------------------------------------------------------------------
def make_ctx(algo, bits):
    if algo == "RSA":
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return {"priv": priv, "pub": priv.public_key()}
    if algo == "AES":
        return {"aead": AESGCM(AESGCM.generate_key(bit_length=bits))}
    while True:  # 3DES: 3 niezalezne klucze DES (24 B)
        k = os.urandom(24)
        if k[:8] != k[8:16] and k[8:16] != k[16:] and k[:8] != k[16:]:
            return {"key": k}


# ---------------------------------------------------------------------------
# Pojedyncze operacje (poza pomiarem: przygotowanie i weryfikacja)
# ---------------------------------------------------------------------------
def encrypt_one(algo, ctx, msg, nonce):
    if algo == "AES":
        return ctx["aead"].encrypt(nonce, msg, None)          # ct || tag
    if algo == "3DES":
        padder = sym_padding.PKCS7(64).padder()
        data = padder.update(msg) + padder.finalize()
        e = Cipher(TripleDES(ctx["key"]), modes.CBC(nonce)).encryptor()
        return e.update(data) + e.finalize()
    return ctx["pub"].encrypt(msg, OAEP)


def decrypt_one(algo, ctx, nonce, ct):
    if algo == "AES":
        return ctx["aead"].decrypt(nonce, ct, None)
    if algo == "3DES":
        d = Cipher(TripleDES(ctx["key"]), modes.CBC(nonce)).decryptor()
        p = d.update(ct) + d.finalize()
        u = sym_padding.PKCS7(64).unpadder()
        return u.update(p) + u.finalize()
    return ctx["priv"].decrypt(ct, OAEP)


def nonce_len(algo):
    return {"AES": 12, "3DES": 8, "RSA": 0}[algo]


def out_size(nonce, ct):
    """Pelny wynik szyfrowania bez klucza: nonce/IV + szyfrogram (AES: z tagiem)."""
    return (len(nonce) if nonce else 0) + len(ct)


# ---------------------------------------------------------------------------
# Mierzone partie (zegar tylko wokol petli operacji)
# ---------------------------------------------------------------------------
def enc_batch(algo, ctx, msg, B):
    """Zwraca (czas partii [s], (ostatni nonce, ostatni szyfrogram))."""
    if algo == "AES":
        enc = ctx["aead"].encrypt
        nonces = [os.urandom(12) for _ in range(B)]
        t0 = pc()
        for nc in nonces:
            out = enc(nc, msg, None)
        t1 = pc()
        return (t1 - t0) / 1e9, (nonces[-1], out)
    if algo == "3DES":
        key = ctx["key"]
        ivs = [os.urandom(8) for _ in range(B)]
        t0 = pc()
        for iv in ivs:
            padder = sym_padding.PKCS7(64).padder()
            data = padder.update(msg) + padder.finalize()
            e = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
            out = e.update(data) + e.finalize()
        t1 = pc()
        return (t1 - t0) / 1e9, (ivs[-1], out)
    enc = ctx["pub"].encrypt
    t0 = pc()
    for _ in range(B):
        out = enc(msg, OAEP)
    t1 = pc()
    return (t1 - t0) / 1e9, (b"", out)


def dec_batch(algo, ctx, inputs):
    """inputs: lista (nonce, szyfrogram). Zwraca (czas partii [s], ostatni wynik)."""
    if algo == "AES":
        dec = ctx["aead"].decrypt
        t0 = pc()
        for nc, ct in inputs:
            out = dec(nc, ct, None)
        t1 = pc()
    elif algo == "3DES":
        key = ctx["key"]
        t0 = pc()
        for iv, ct in inputs:
            d = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
            p = d.update(ct) + d.finalize()
            u = sym_padding.PKCS7(64).unpadder()
            out = u.update(p) + u.finalize()
        t1 = pc()
    else:
        dec = ctx["priv"].decrypt
        t0 = pc()
        for _, ct in inputs:
            out = dec(ct, OAEP)
        t1 = pc()
    return (t1 - t0) / 1e9, out


# ---------------------------------------------------------------------------
# Przygotowanie zadania (rozgrzewka, kalibracja partii, szyfrogramy wejsciowe)
# ---------------------------------------------------------------------------
def calibrate(fn, target_s):
    """Rozmiar partii B: mediana kilku pojedynczych operacji -> B ~ target/t."""
    times, total = [], 0.0
    while len(times) < 5 and total < 0.5:
        t = fn()
        times.append(t)
        total += t
    t1 = statistics.median(times)
    return max(1, min(MAX_BATCH, math.ceil(target_s / max(t1, 1e-9))))


def prepare_task(name, algo, ctx, size, msg, target_batch_s, warmups):
    # rozgrzewka (odrzucana)
    for _ in range(warmups):
        enc_batch(algo, ctx, msg, 1)
        nc = os.urandom(nonce_len(algo))
        decrypt_one(algo, ctx, nc, encrypt_one(algo, ctx, msg, nc))

    B_enc = calibrate(lambda: enc_batch(algo, ctx, msg, 1)[0], target_batch_s)

    # szyfrogramy wejsciowe do deszyfrowania (poza pomiarem)
    def build(B):
        pairs = []
        for _ in range(B):
            nc = os.urandom(nonce_len(algo))
            pairs.append((nc, encrypt_one(algo, ctx, msg, nc)))
        return pairs

    one = build(1)
    B_dec = calibrate(lambda: dec_batch(algo, ctx, one)[0], target_batch_s)
    inputs = build(B_dec)

    # weryfikacja WSZYSTKICH szyfrogramow wejsciowych bajt po bajcie
    for nc, ct in inputs:
        if decrypt_one(algo, ctx, nc, ct) != msg:
            sys.exit(f"BLAD: niezgodnosc po deszyfrowaniu ({name}, {size} B)")
    sizes_out = {out_size(nc, ct) for nc, ct in inputs}
    assert len(sizes_out) == 1, "rozmiar wyniku powinien byc stalym dla danego Sin"
    return {"name": name, "algo": algo, "ctx": ctx, "size": size, "msg": msg,
            "B_enc": B_enc, "B_dec": B_dec, "dec_inputs": inputs,
            "S_out": sizes_out.pop()}


def measure(task, op):
    """Jeden pomiar. Zwraca (batch_size, czas partii, czas na operacje, ok)."""
    algo, ctx, msg = task["algo"], task["ctx"], task["msg"]
    try:
        if op == "enc":
            B = task["B_enc"]
            t, (nc, ct) = enc_batch(algo, ctx, msg, B)
            ok = decrypt_one(algo, ctx, nc, ct) == msg       # poza pomiarem czasu
        else:
            B = task["B_dec"]
            t, out = dec_batch(algo, ctx, task["dec_inputs"])
            ok = out == msg
    except Exception:
        return (task["B_enc"] if op == "enc" else task["B_dec"]), float("nan"), float("nan"), False
    return B, t, t / B, ok


# ---------------------------------------------------------------------------
# Statystyki
# ---------------------------------------------------------------------------
def percentile(sorted_vals, p):
    k = (len(sorted_vals) - 1) * p / 100
    f = math.floor(k)
    c = min(f + 1, len(sorted_vals) - 1)
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def describe(vals):
    s = sorted(vals)
    return {"n_obs": len(vals), "mean_s": statistics.mean(vals),
            "median_s": statistics.median(vals), "p95_s": percentile(s, 95),
            "std_s": statistics.stdev(vals) if len(vals) > 1 else float("nan")}


def size_label(n):
    if n >= 1024 ** 2:
        return f"{n // 1024 ** 2} MB"
    if n >= 1024:
        return f"{n // 1024} KB"
    return f"{n} B"


def fmt_time(s):
    if s != s:
        return "n/d"
    if s >= 1:
        return f"{s:.3f} s"
    if s >= 1e-3:
        return f"{s * 1e3:.3f} ms"
    return f"{s * 1e6:.2f} us"


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# Wykresy
# ---------------------------------------------------------------------------
def make_plots(raw, stats_rows, metric_rows, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n[!] Brak matplotlib: pomijam wykresy (pip install matplotlib).")
        return

    colors = {"RSA-2048": "tab:blue", "RSA-3072": "tab:red", "AES-128-GCM": "tab:green",
              "AES-256-GCM": "tab:orange", "3DES-CBC": "tab:purple"}
    groups = [("RSA-OAEP (kr\u00f3tkie wiadomo\u015bci)", ["RSA-2048", "RSA-3072"]),
              ("AES-GCM / 3DES-CBC", ["AES-128-GCM", "AES-256-GCM", "3DES-CBC"])]

    def style(ax, ylabel, sizes, title):
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xticks(sizes)
        ax.set_xticklabels([size_label(s) for s in sizes], rotation=45, ha="right", fontsize=8)
        ax.minorticks_off()
        ax.set_xlabel("Rozmiar wiadomo\u015bci")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, which="major", alpha=0.3)
        ax.legend(fontsize=8)

    def time_fig(op, fname, title):
        fig, axes = plt.subplots(1, 2, figsize=(13, 5))
        for ax, (gt, cfgs) in zip(axes, groups):
            sizes = sorted({s["size_B"] for s in stats_rows if s["config"] in cfgs})
            for cfg in cfgs:
                pts = [r for r in raw if r["config"] == cfg and r["op"] == op and r["ok"]]
                ax.scatter([r["size_B"] for r in pts], [r["t_per_op_s"] * 1e6 for r in pts],
                           s=8, alpha=0.25, color=colors[cfg])
                rows = sorted([s for s in stats_rows if s["config"] == cfg and s["op"] == op],
                              key=lambda s: s["size_B"])
                ax.plot([s["size_B"] for s in rows], [s["median_s"] * 1e6 for s in rows],
                        "o-", color=colors[cfg], label=f"{cfg} (mediana)")
            style(ax, "Czas operacji [\u00b5s]", sizes, gt)
        fig.suptitle(title)
        fig.tight_layout()
        fig.savefig(outdir / fname, dpi=150)
        plt.close(fig)
        print("Zapisano wykres:", outdir / fname)

    time_fig("enc", "exp2_czas_szyfrowania.png", "Mediana czasu szyfrowania (n = 30 pomiar\u00f3w)")
    time_fig("dec", "exp2_czas_deszyfrowania.png", "Mediana czasu deszyfrowania (n = 30 pomiar\u00f3w)")

    # przepustowosc
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, (gt, cfgs) in zip(axes, groups):
        sizes = sorted({m["size_B"] for m in metric_rows if m["config"] in cfgs})
        for cfg in cfgs:
            rows = sorted([m for m in metric_rows if m["config"] == cfg], key=lambda m: m["size_B"])
            xs = [m["size_B"] for m in rows]
            ax.plot(xs, [m["P_enc_MiBps"] for m in rows], "o-", color=colors[cfg],
                    label=f"{cfg} szyfrowanie")
            ax.plot(xs, [m["P_dec_MiBps"] for m in rows], "s--", color=colors[cfg],
                    mfc="none", label=f"{cfg} deszyfrowanie")
        style(ax, "Przepustowo\u015b\u0107 [MiB/s]", sizes,
              gt if "RSA" not in gt else "RSA-OAEP (tylko kr\u00f3tkie wiadomo\u015bci, nie pliki)")
    fig.suptitle("Przepustowo\u015b\u0107 P = S / t_med")
    fig.tight_layout()
    fig.savefig(outdir / "exp2_przepustowosc.png", dpi=150)
    plt.close(fig)
    print("Zapisano wykres:", outdir / "exp2_przepustowosc.png")

    # narzut procentowy
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, (gt, cfgs) in zip(axes, groups):
        sizes = sorted({m["size_B"] for m in metric_rows if m["config"] in cfgs})
        for cfg in cfgs:
            rows = sorted([m for m in metric_rows if m["config"] == cfg], key=lambda m: m["size_B"])
            ax.plot([m["size_B"] for m in rows], [m["overhead_pct"] for m in rows],
                    "o-", color=colors[cfg], label=cfg)
        style(ax, "Narzut O [%]", sizes, gt)
    fig.suptitle("Narzut procentowy O = (S_out - S_in) / S_in")
    fig.tight_layout()
    fig.savefig(outdir / "exp2_narzut.png", dpi=150)
    plt.close(fig)
    print("Zapisano wykres:", outdir / "exp2_narzut.png")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=MIN_REPS, help="pomiarow na konfiguracje/rozmiar/operacje (min. 30)")
    ap.add_argument("--quick", action="store_true", help="szybki test skryptu (nie do sprawozdania)")
    ap.add_argument("--out", default=None, help="katalog wynikow")
    args = ap.parse_args()

    sizes_sym, sizes_rsa = SIZES_SYM, SIZES_RSA
    target_batch, warmups = TARGET_BATCH_S, WARMUP_OPS
    if args.quick:
        args.reps = min(args.reps, 5)
        sizes_sym = [s for s in SIZES_SYM if s <= 1024 ** 2]
        target_batch, warmups = 2e-4, 2
    elif args.reps < MIN_REPS:
        sys.exit(f"Zadanie wymaga co najmniej {MIN_REPS} pomiarow.")

    outdir = Path(args.out) if args.out else Path(__file__).resolve().parent / "wyniki_eksp2"
    outdir.mkdir(parents=True, exist_ok=True)

    print("=" * 74)
    print("ZTKiK Lab 2 | Eksperyment 2: szyfrowanie i deszyfrowanie")
    print("=" * 74)
    print(f"Python {platform.python_version()}, cryptography {cryptography.__version__}, "
          f"{platform.system()} {platform.release()}")
    if args.quick:
        print("[TRYB QUICK] wyniki tylko do testu skryptu")

    # --- przygotowanie: klucze, dane, kalibracja --------------------------
    print("\n[1] Przygotowanie (klucze, dane, rozgrzewka, kalibracja partii)")
    messages = {s: os.urandom(s) for s in set(sizes_sym) | set(sizes_rsa)}
    tasks = []
    for name, (algo, bits) in CONFIGS.items():
        print(f"  {name}: generowanie klucza...", flush=True)
        ctx = make_ctx(algo, bits)
        for size in (sizes_rsa if algo == "RSA" else sizes_sym):
            t = prepare_task(name, algo, ctx, size, messages[size], target_batch, warmups)
            tasks.append(t)
            print(f"    {size_label(size):>6}: partia szyfrowania B={t['B_enc']:<6} "
                  f"deszyfrowania B={t['B_dec']:<6} S_out={t['S_out']} B", flush=True)

    # --- pomiary ----------------------------------------------------------
    rng = random.Random(SEED)
    raw = []
    print(f"\n[2] Pomiary: {args.reps} rund x {len(tasks)} zadan x 2 operacje "
          f"(losowa kolejnosc, seed={SEED})")
    gc.collect()
    gc.disable()
    t_start = time.time()
    try:
        for rep in range(1, args.reps + 1):
            order = tasks[:]
            rng.shuffle(order)
            for pos, task in enumerate(order, 1):
                ops = ["enc", "dec"]
                rng.shuffle(ops)
                for op in ops:
                    B, tb, tpo, ok = measure(task, op)
                    raw.append({"round": rep, "run_order": pos, "config": task["name"],
                                "size_B": task["size"], "op": op, "batch_size": B,
                                "batch_time_s": tb, "t_per_op_s": tpo, "ok": ok})
            el = time.time() - t_start
            print(f"  runda {rep}/{args.reps} gotowa, uplynelo {el:.0f} s, "
                  f"szacowany koniec za {el / rep * (args.reps - rep):.0f} s", flush=True)
    finally:
        gc.enable()

    # --- statystyki -------------------------------------------------------
    stats_rows = []
    keys = [(t["name"], t["size"]) for t in tasks]
    for name, size in keys:
        for op in ("enc", "dec"):
            cell = [r for r in raw if r["config"] == name and r["size_B"] == size and r["op"] == op]
            good = [r["t_per_op_s"] for r in cell if r["ok"]]
            d = describe(good) if good else {"n_obs": 0, "mean_s": float("nan"),
                                              "median_s": float("nan"), "p95_s": float("nan"),
                                              "std_s": float("nan")}
            stats_rows.append({"config": name, "size_B": size, "op": op,
                               "batch_size": cell[0]["batch_size"],
                               "n_failed": len(cell) - len(good), **d})
    lookup = {(s["config"], s["size_B"], s["op"]): s for s in stats_rows}

    metric_rows = []
    for t in tasks:
        name, size = t["name"], t["size"]
        tenc = lookup[(name, size, "enc")]["median_s"]
        tdec = lookup[(name, size, "dec")]["median_s"]
        s_mib = size / 1024 ** 2
        d_s = t["S_out"] - size
        metric_rows.append({
            "config": name, "size_B": size, "S_in_B": size, "S_out_B": t["S_out"],
            "delta_S_B": d_s, "overhead_pct": d_s / size * 100,
            "t_med_enc_s": tenc, "t_med_dec_s": tdec,
            "P_enc_MiBps": s_mib / tenc, "P_dec_MiBps": s_mib / tdec})

    write_csv(outdir / "exp2_surowe.csv", raw,
              ["round", "run_order", "config", "size_B", "op", "batch_size",
               "batch_time_s", "t_per_op_s", "ok"])
    write_csv(outdir / "exp2_statystyki.csv", stats_rows,
              ["config", "size_B", "op", "batch_size", "n_obs", "n_failed",
               "mean_s", "median_s", "p95_s", "std_s"])
    write_csv(outdir / "exp2_przepustowosc_narzut.csv", metric_rows,
              ["config", "size_B", "S_in_B", "S_out_B", "delta_S_B", "overhead_pct",
               "t_med_enc_s", "t_med_dec_s", "P_enc_MiBps", "P_dec_MiBps"])
    meta = {"python": platform.python_version(), "cryptography": cryptography.__version__,
            "system": f"{platform.system()} {platform.release()} {platform.version()}",
            "machine": platform.machine(), "cpu_count": os.cpu_count(), "seed_kolejnosci": SEED,
            "reps": args.reps, "warmup_ops": warmups, "target_batch_s": target_batch,
            "quick": args.quick, "sizes_sym_B": sizes_sym, "sizes_rsa_B": sizes_rsa,
            "batch_sizes": {f"{t['name']}|{t['size']}": {"enc": t["B_enc"], "dec": t["B_dec"]}
                            for t in tasks}}
    (outdir / "exp2_parametry.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # --- wydruk -----------------------------------------------------------
    for op, title in (("enc", "SZYFROWANIE"), ("dec", "DESZYFROWANIE")):
        print(f"\n{title}: statystyki z n obserwacji (czas jednej operacji)")
        print(f"{'Konfig':<13}{'Rozmiar':>8}{'n':>4}{'B':>7}{'srednia':>13}{'mediana':>13}"
              f"{'p95':>13}{'odch.std':>13}")
        prev = None
        for t in tasks:
            s = lookup[(t["name"], t["size"], op)]
            if prev and t["name"] != prev:
                print()
            prev = t["name"]
            print(f"{t['name']:<13}{size_label(t['size']):>8}{s['n_obs']:>4}{s['batch_size']:>7}"
                  f"{fmt_time(s['mean_s']):>13}{fmt_time(s['median_s']):>13}"
                  f"{fmt_time(s['p95_s']):>13}{fmt_time(s['std_s']):>13}"
                  + (f"  [bledy: {s['n_failed']}]" if s["n_failed"] else ""))

    print("\nPRZEPUSTOWOSC I NARZUT")
    print(f"{'Konfig':<13}{'Rozmiar':>8}{'S_in':>10}{'S_out':>10}{'dS':>6}{'O [%]':>10}"
          f"{'P_enc MiB/s':>14}{'P_dec MiB/s':>14}")
    prev = None
    for m in metric_rows:
        if prev and m["config"] != prev:
            print()
        prev = m["config"]
        print(f"{m['config']:<13}{size_label(m['size_B']):>8}{m['S_in_B']:>10}{m['S_out_B']:>10}"
              f"{m['delta_S_B']:>6}{m['overhead_pct']:>10.2f}{m['P_enc_MiBps']:>14.2f}"
              f"{m['P_dec_MiBps']:>14.2f}")

    print("\nPliki wynikowe w:", outdir)
    make_plots(raw, stats_rows, metric_rows, outdir)


if __name__ == "__main__":
    main()