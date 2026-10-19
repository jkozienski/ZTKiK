#nauczyc projektować uczciwy pomiar
#przemysleć dobór konfigu w ekspreymencie
#jak konrolusie sie warunki
#jak replikowac takie porównanie
#podstawowe elementy statystyczne
#jezeli nie ma jakis trybów pracy algorytmow uzyj innych ale opisz jak one działaja
#wykonaj 2 podstawowe eksperymenty i oblicz 2 metryki
#(licz srednia i mediana)
#nie licz 95%percentyl dla 5 


#!/usr/bin/env python3
"""
ZTKiK Lab 2: Porownanie RSA, AES, 3DES
Krok 1: Przygotowanie srodowiska

Skrypt:
  1. zbiera informacje o srodowisku (do sekcji 5.1 sprawozdania),
  2. definiuje konfiguracje z tabeli 1 (wspolny modul dla kolejnych krokow),
  3. wykonuje testy poprawnosci (round-trip, rozmiary wyjscia, limity RSA-OAEP),
  4. sprawdza rozdzielczosc zegara uzywanego do pomiarow.

Biblioteka: pyca/cryptography (backend OpenSSL).
"""
import os
import sys
import time
import platform
from dataclasses import dataclass

import cryptography
from cryptography.hazmat.backends.openssl.backend import backend as ossl_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 3DES w cryptography >= 43 jest w module "decrepit" (algorytm przestarzaly)
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # starsze wersje biblioteki
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


# ---------------------------------------------------------------------------
# Konfiguracje z tabeli 1
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Config:
    name: str
    algo: str          # "RSA" | "AES" | "3DES"
    key_bits: int      # RSA: dlugosc modulu; AES: 128/256; 3DES: 168 (efektywne)
    mode: str          # opis schematu

CONFIGS = [
    Config("RSA-2048", "RSA", 2048, "OAEP, SHA-256, MGF1-SHA256"),
    Config("RSA-3072", "RSA", 3072, "OAEP, SHA-256, MGF1-SHA256"),
    Config("AES-128-GCM", "AES", 128, "GCM, nonce 96 b, tag 128 b"),
    Config("AES-256-GCM", "AES", 256, "GCM, nonce 96 b, tag 128 b"),
    Config("3DES-CBC", "3DES", 168, "CBC, IV 64 b, PKCS#7"),
]

# Rozmiary wiadomosci z eksperymentu 2
SIZES_SYM = [128, 512, 2 * 1024, 8 * 1024, 32 * 1024,
             1024**2, 4 * 1024**2, 16 * 1024**2]
SIZES_RSA = [16, 32, 64, 128, 190]

AES_NONCE_LEN = 12   # 96 bitow
AES_TAG_LEN = 16     # 128 bitow
DES_IV_LEN = 8       # 64 bity
DES_BLOCK = 8


# ---------------------------------------------------------------------------
# Generowanie kluczy
# ---------------------------------------------------------------------------
def gen_rsa(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def gen_aes(bits):
    return AESGCM.generate_key(bit_length=bits)

def gen_3des():
    """3 niezalezne klucze DES = 24 bajty (192 b z bitami parzystosci, 168 b materialu).
    OpenSSL ignoruje bity parzystosci, wiec losowe 24 B daje 168 b entropii.
    Odrzucamy klucze, w ktorych K1==K2 lub K2==K3 (degeneracja do 1DES/2DES),
    co biblioteka i tak by odrzucila."""
    while True:
        k = os.urandom(24)
        k1, k2, k3 = k[:8], k[8:16], k[16:]
        if k1 != k2 and k2 != k3 and k1 != k3:
            return k


# ---------------------------------------------------------------------------
# Szyfrowanie / deszyfrowanie
# ---------------------------------------------------------------------------
_OAEP = asym_padding.OAEP(
    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

def rsa_encrypt(pub, data):
    return pub.encrypt(data, _OAEP)

def rsa_decrypt(priv, ct):
    return priv.decrypt(ct, _OAEP)

def aes_encrypt(key, data):
    """Wynik: nonce(12) || szyfrogram || tag(16). Zwracamy komplet, bo
    narzut liczymy dla pelnego wyniku (bez klucza)."""
    nonce = os.urandom(AES_NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, data, None)  # ct||tag

def aes_decrypt(key, blob):
    nonce, rest = blob[:AES_NONCE_LEN], blob[AES_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, rest, None)

def des3_encrypt(key, data):
    """Wynik: IV(8) || szyfrogram CBC z PKCS#7."""
    iv = os.urandom(DES_IV_LEN)
    padder = padding.PKCS7(64).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()

def des3_decrypt(key, blob):
    iv, ct = blob[:DES_IV_LEN], blob[DES_IV_LEN:]
    dec = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ---------------------------------------------------------------------------
# Informacje o srodowisku
# ---------------------------------------------------------------------------
def _read_first(path, key):
    try:
        with open(path) as f:
            for line in f:
                if line.startswith(key):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "n/d"

def _cpu_name():
    """Nazwa procesora: Windows (rejestr), Linux (/proc), macOS (sysctl)."""
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as k:
                return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
        except OSError:
            return platform.processor() or "n/d"
    if sys.platform == "darwin":
        try:
            import subprocess
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        except Exception:
            return "n/d"
    name = _read_first("/proc/cpuinfo", "model name")
    return name if name != "n/d" else (platform.processor() or "n/d")

def _ram_bytes():
    """Calkowita pamiec RAM w bajtach (lub None)."""
    if sys.platform == "win32":
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return st.ullTotalPhys
        return None
    if sys.platform == "darwin":
        try:
            import subprocess
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))
        except Exception:
            return None
    kb = _read_first("/proc/meminfo", "MemTotal").split()
    try:
        return int(kb[0]) * 1024
    except (ValueError, IndexError):
        return None

def _os_name():
    system, release = platform.system(), platform.release()
    # Windows 11 zglasza sie jako "10"; rozpoznajemy po numerze kompilacji
    if system == "Windows":
        try:
            build = int(platform.version().split(".")[2])
            if build >= 22000:
                release = "11"
        except (IndexError, ValueError):
            pass
        return f"Windows {release} (build {platform.version()}, {platform.machine()})"
    return f"{system} {release} ({platform.machine()})"

def environment_info():
    ram = _ram_bytes()
    return {
        "Jezyk": f"Python {platform.python_version()} ({platform.python_implementation()})",
        "Biblioteka": f"pyca/cryptography {cryptography.__version__}",
        "Backend": ossl_backend.openssl_version_text(),
        "Procesor": _cpu_name(),
        "Liczba CPU": f"{os.cpu_count()} (watki logiczne)",
        "RAM": f"{ram / 1024**3:.1f} GB" if ram else "n/d",
        "System": _os_name(),
        "Zegar pomiarowy": "time.perf_counter_ns()",
    }


def clock_resolution(samples=100_000):
    """Najmniejsza niezerowa roznica kolejnych odczytow perf_counter_ns."""
    deltas = []
    prev = time.perf_counter_ns()
    for _ in range(samples):
        cur = time.perf_counter_ns()
        if cur != prev:
            deltas.append(cur - prev)
            prev = cur
    return min(deltas) if deltas else None


# ---------------------------------------------------------------------------
# Testy poprawnosci
# ---------------------------------------------------------------------------
def selftest():
    results = []

    # RSA
    for cfg in CONFIGS:
        if cfg.algo != "RSA":
            continue
        priv = gen_rsa(cfg.key_bits)
        pub = priv.public_key()
        max_len = cfg.key_bits // 8 - 2 * 32 - 2   # k - 2*hLen - 2
        ok_all = True
        for n in SIZES_RSA:
            msg = os.urandom(n)
            ct = rsa_encrypt(pub, msg)
            ok_all &= (rsa_decrypt(priv, ct) == msg) and (len(ct) == cfg.key_bits // 8)
        # test granicy: max_len musi przejsc, max_len+1 musi zawiesc
        edge_ok = rsa_decrypt(priv, rsa_encrypt(pub, os.urandom(max_len))) is not None
        try:
            rsa_encrypt(pub, os.urandom(max_len + 1))
            edge_fail = False
        except ValueError:
            edge_fail = True
        results.append((cfg.name, ok_all and edge_ok and edge_fail,
                        f"max wiadomosc = {max_len} B, szyfrogram = {cfg.key_bits // 8} B"))

    # AES
    for cfg in CONFIGS:
        if cfg.algo != "AES":
            continue
        key = gen_aes(cfg.key_bits)
        ok_all = True
        for n in SIZES_SYM[:5]:
            msg = os.urandom(n)
            blob = aes_encrypt(key, msg)
            ok_all &= (aes_decrypt(key, blob) == msg) and (len(blob) == n + 12 + 16)
        # uszkodzony tag musi zostac wykryty
        blob = bytearray(aes_encrypt(key, b"x" * 64)); blob[-1] ^= 1
        try:
            aes_decrypt(key, bytes(blob)); tamper = False
        except Exception:
            tamper = True
        results.append((cfg.name, ok_all and tamper,
                        "narzut staly = 28 B (12 nonce + 16 tag), wykrywa modyfikacje"))

    # 3DES
    key = gen_3des()
    ok_all = True
    for n in SIZES_SYM[:5] + [0, 1, 7, 8, 9]:
        msg = os.urandom(n)
        blob = des3_encrypt(key, msg)
        expected = DES_IV_LEN + (n // DES_BLOCK + 1) * DES_BLOCK
        ok_all &= (des3_decrypt(key, blob) == msg) and (len(blob) == expected)
    results.append(("3DES-CBC", ok_all,
                    "narzut = 8 B IV + 1..8 B dopelnienia PKCS#7"))
    return results


def main():
    print("=" * 66)
    print("ZTKiK Lab 2 | Krok 1: Przygotowanie srodowiska")
    print("=" * 66)

    print("\n[1] Srodowisko (do sekcji 5.1 sprawozdania)")
    for k, v in environment_info().items():
        print(f"  {k:<16}: {v}")
    res = clock_resolution()
    print(f"  {'Rozdz. zegara':<16}: ~{res} ns")

    print("\n[2] Konfiguracje (tabela 1)")
    print(f"  {'Nazwa':<13}{'Klucz [b]':<11}Schemat")
    for c in CONFIGS:
        print(f"  {c.name:<13}{c.key_bits:<11}{c.mode}")

    print("\n[3] Rozmiary wiadomosci (eksperyment 2)")
    print("  AES/3DES [B]:", SIZES_SYM)
    print("  RSA [B]     :", SIZES_RSA)

    print("\n[4] Testy poprawnosci")
    all_ok = True
    for name, ok, note in selftest():
        all_ok &= ok
        print(f"  [{'OK' if ok else 'BLAD'}] {name:<13} {note}")

    print("\nWynik:", "srodowisko gotowe" if all_ok else "WYKRYTO BLEDY")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())