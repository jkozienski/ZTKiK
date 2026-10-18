# -*- coding: utf-8 -*-
"""
Lamanie szyfru afinicznego:  szyfrowanie  y = (a*x + b) mod 26
"""

from math import gcd
from collections import Counter

# ----------------------------------------------------------------------
# 1. DANE: tekst do zlamania i tabela 2.1 (prawdopodobienstwa liter)
# ----------------------------------------------------------------------

CIPHERTEXT = """GZAO WNGZ M PQSO, JQCJ WN QZ PJO UWQOP ZQCJP IEY, PJOBO KMI M PQZY IPMB ZMSOH NQN. NQN KMI IG ISMLL PJMP JO KMI MVBMQH JQI LQCJP KMI PGG KOME PG TO IOOZ. ODOBY ODOZQZC, PJO TQC IPMBI KGWLH CLGK TBQCJPLY, MZH NQN KGWLH JQHO TOJQZH M VLWVVY ALGWH"""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Prawdopodobienstwo wystapienia kazdej litery w jezyku angielskim
PROBABILITY = {
    "A": 0.082, "B": 0.015, "C": 0.028, "D": 0.043, "E": 0.127,
    "F": 0.022, "G": 0.020, "H": 0.061, "I": 0.070, "J": 0.002,
    "K": 0.008, "L": 0.040, "M": 0.024, "N": 0.067, "O": 0.075,
    "P": 0.019, "Q": 0.001, "R": 0.060, "S": 0.063, "T": 0.091,
    "U": 0.028, "V": 0.010, "W": 0.023, "X": 0.001, "Y": 0.020,
    "Z": 0.001,
}

# Litery angielskie od najczestszej do najrzadszej: E, T, A, O, I, ...
ENGLISH_LETTERS = sorted(ALPHABET, key=lambda letter: PROBABILITY[letter], reverse=True)


# ----------------------------------------------------------------------
# 2. FUNKCJE POMOCNICZE
# ----------------------------------------------------------------------

def letter_to_number(letter):
    """Zamienia litere na liczbe: A->0, B->1, ..., Z->25."""
    return ord(letter) - ord("A")


def number_to_letter(number):
    """Zamienia liczbe na litere: 0->A, 1->B, ..., 25->Z (liczba brana modulo 26)."""
    return chr(number % 26 + ord("A"))


def only_letters(text):
    """Zostawia w tekscie same litery A-Z (usuwa spacje, kropki itd.)."""
    return "".join(c for c in text.upper() if c.isascii() and c.isalpha())


def count_frequencies(text):
    """
    Liczy, ile razy kazda litera wystepuje w tekscie.
    Zwraca slownik z wszystkimi 26 literami: litera -> liczba wystapien
    (litery, ktorych nie ma w tekscie, maja wartosc 0).
    """
    counts = Counter(text)
    return {letter: counts[letter] for letter in ALPHABET}


def modular_inverse(number, modulus):
    """
    Zwraca takie x, ze (number * x) % modulus == 1 (odwrotnosc modulo).
    Jesli nie istnieje (gdy gcd(number, modulus) != 1), zwraca None.
    """
    try:
        return pow(number, -1, modulus)
    except ValueError:      # brak odwrotnosci
        return None


def solve_equation(c, d):
    """
    Rozwiazuje rownanie   c * a = d  (mod 26)   wzgledem a.
    Zwraca liste wszystkich rozwiazan a (moze byc 0, 1 lub 2 rozwiazania).

    Zasada:
      g = gcd(c, 26)
      - jesli d nie dzieli sie przez g  -> brak rozwiazan
      - w przeciwnym razie dzielimy cale rownanie (i modulo) przez g,
        liczymy odwrotnosc i dostajemy rozwiazanie a0 modulo 26/g.
        Wtedy rozwiazaniami sa: a0, a0 + 26/g, a0 + 2*26/g, ...
    """
    g = gcd(c, 26)
    if d % g != 0:
        return []

    small_c = c // g
    small_d = d // g
    small_modulus = 26 // g

    inverse = modular_inverse(small_c, small_modulus)
    a0 = (small_d * inverse) % small_modulus

    solutions = []
    for k in range(g):
        solutions.append(a0 + k * small_modulus)
    return solutions


def decrypt(text, a, b):
    """
    Deszyfrowanie:  x = a^(-1) * (y - b)  mod 26
    Znaki, ktore nie sa literami (spacje, przecinki...), zostaja bez zmian.
    """
    a_inverse = modular_inverse(a, 26)
    result = ""
    for char in text.upper():
        if char in ALPHABET:
            y = letter_to_number(char)
            x = (a_inverse * (y - b)) % 26
            result = result + number_to_letter(x)
        else:
            result = result + char
    return result


def score_text(text):
    """
    Srednie prawdopodobienstwo liter w tekscie (wg tabeli 2.1).
    Tekst angielski daje ok. 0.065, losowy ciag liter duzo mniej (ok. 0.04-0.05).
    """
    total = 0
    for letter in text:
        total = total + PROBABILITY[letter]
    return total / len(text)


def print_histogram(frequencies):
    """Prosty histogram tekstowy: kazdy # to jedno wystapienie litery"""
    for letter in ALPHABET:
        print(f"{letter} | {'#' * frequencies[letter]} {frequencies[letter]}")


def save_histogram_png(frequencies, filename="histogram.png"):
    """Zapisuje histogram jako obrazek (potrzebuje biblioteki matplotlib)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(Brak matplotlib, pomijam zapis histogram.png)")
        return

    plt.figure(figsize=(9, 4))
    plt.bar(list(ALPHABET), [frequencies[letter] for letter in ALPHABET])
    plt.title("Histogram czestosci liter w szyfrogramie")
    plt.xlabel("Litera")
    plt.ylabel("Liczba wystapien")
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.close()
    print(f"Zapisano {filename}")


# ----------------------------------------------------------------------
# 3. GLOWNY PROGRAM
# ----------------------------------------------------------------------

# Szerokosci kolumn tabeli: hipoteza, uklad rownan, klucz, wynik, tekst
COLUMN_WIDTHS = (10, 17, 12, 26, 51)


def print_row(*cells):
    """Drukuje jeden wiersz tabeli, kazda komorke dopelniona spacjami do szerokosci kolumny."""
    padded = [str(cell).ljust(width) for cell, width in zip(cells, COLUMN_WIDTHS)]
    print("  ".join(padded).rstrip())


def print_header():
    print_row("Hipoteza", "Układ równań", "Klucz", "Wynik", "Odszyfrowany tekst")
    print("  ".join("-" * width for width in COLUMN_WIDTHS))


def main():
    # --- Krok 1: czestosci liter w szyfrogramie ---
    letters = only_letters(CIPHERTEXT)
    frequencies = count_frequencies(letters)

    print(f"Dlugosc szyfrogramu: {len(letters)} liter\n")
    print("HISTOGRAM CZESTOSCI LITER:")
    print_histogram(frequencies)
    save_histogram_png(frequencies)

    # 5 najczestszych liter szyfrogramu (od najczestszej)
    top_cipher = sorted(ALPHABET, key=lambda letter: frequencies[letter], reverse=True)[:5]
    print("\nNajczestsze litery szyfrogramu:", [(l, frequencies[l]) for l in top_cipher])

    # --- Krok 2: hipotezy  E -> c1,  T -> c2  i uklad rownan ---
    x1 = letter_to_number("E")   # 4
    x2 = letter_to_number("T")   # 19
    THRESHOLD = 0.058            # powyzej tej oceny tekst uznajemy za sensowny

    print("\nOBLICZENIA PROWADZACE DO KLUCZA \n")
    print_header()

    results = []    # poprawne klucze: (score, a, b)
    checked = set()

    for c1 in top_cipher:                  # E -> c1
        for c2 in top_cipher:              # T -> c2
            if c1 == c2:
                continue
            y1 = letter_to_number(c1)
            y2 = letter_to_number(c2)

            # Uklad:  a*x1 + b = y1,  a*x2 + b = y2   (mod 26)
            # Odejmujemy: a*(x2 - x1) = (y2 - y1)  (mod 26)
            a = solve_equation((x2 - x1) % 26, (y2 - y1) % 26)[0]
            b = (y1 - a * x1) % 26

            hypothesis = f"E→{c1}, T→{c2}"
            equations = f"{x1}a+b≡{y1}, {x2}a+b≡{y2}"
            key = f"a={a}, b={b}"

            g = gcd(a, 26)
            if g != 1:
                print_row(hypothesis, equations, key, f"NIEPOPRAWNY (gcd({a},26)={g})", "")
                continue

            plaintext = decrypt(letters, a, b)
            score = score_text(plaintext)
            verdict = "SENSOWNY" if score >= THRESHOLD else "bezsensowny"
            print_row(hypothesis, equations, key, f"score={score:.4f} {verdict}", plaintext[:50]+ "…")

            if (a, b) not in checked:
                checked.add((a, b))
                results.append((score, a, b))

    # --- Krok 3: wybor najlepszego klucza ---
    results.sort(reverse=True)
    best_score, a, b = results[0]

# 3 najlepiej dopasowane klucze (najwyzszy score) i tekst odszyfrowany kazdym z nich
    print("\n3 NAJLEPIEJ DOPASOWANE KLUCZE")
    for place, (score, key_a, key_b) in enumerate(results[:3], start=1):
        print(f"\n{place}. a={key_a}, b={key_b}, score={score:.4f}")
        print("   " + " ".join(decrypt(CIPHERTEXT, key_a, key_b).split()))


    print("\nWYBOR KLUCZA")
    print(f"a = {a}, b = {b}, odwrotnosc a = {modular_inverse(a, 26)}")
    if len(results) > 1:
        print(f"Ocena: {best_score:.4f} (drugi wynik: {results[1][0]:.4f})")
    else:
        print(f"Ocena: {best_score:.4f}")

    print("\nTekst jawny:")
    print(" ".join(decrypt(CIPHERTEXT, a, b).split()))


if __name__ == "__main__":
    main()
