# -*- coding: utf-8 -*-
"""
Lamanie szyfru afinicznego:  szyfrowanie  y = (a*x + b) mod 26

Metoda: NIE sprawdzamy wszystkich kluczy (to byłby brute force).
Zamiast tego robimy zgadywanie na podstawie czestosci liter i
rozwiazujemy UKLAD ROWNAN, z ktorego wychodza a i b.

Przyklad:
  zgadujemy: litera E (x=4)  w szyfrogramie to R (y=17)
  zgadujemy: litera I (x=8)  w szyfrogramie to D (y=3)
  Uklad:   a*4 + b = 17  (mod 26)
           a*8 + b = 3   (mod 26)
  Odejmujemy rownania i mamy rownanie tylko z "a", potem liczymy "b".
"""

from math import gcd
from collections import Counter

# ----------------------------------------------------------------------
# 1. DANE: tekst do zlamania i tabela 2.1 (prawdopodobienstwa liter)
# ----------------------------------------------------------------------

CIPHERTEXT = """AVSC QAPC ZRC UZAPQ WU RAOLWVM, IVX RILH RWXEVXCP ZRWU SPIXLC-RAAX IVX SAJCPLWX  QY SRWLX ULCCFU AV. ZRCPC WU VA ANUZISLC NEZ MPCMAPY'U OAAX IVX AVC NIPC RWLL  ORCPCNY ZRC RIYUZISG- IVX PAAH-LCJCLLWVM OWVX, NPCX AV ZRC IZLIVZWS, SIV NC UZIYCX"""

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

def main():
    # --- Krok 1: czestosci liter w szyfrogramie ---
    letters = only_letters(CIPHERTEXT)
    frequencies = count_frequencies(letters)

    print(f"Dlugosc szyfrogramu: {len(letters)} liter\n")
    print("HISTOGRAM CZESTOSCI LITER:")
    print_histogram(frequencies)
    save_histogram_png(frequencies)

    # Litery szyfrogramu od najczestszej do najrzadszej
    cipher_letters_sorted = sorted(ALPHABET, key=lambda letter: frequencies[letter], reverse=True)

    # Bierzemy po 5 najczestszych liter z kazdej strony
    top_cipher = cipher_letters_sorted[:5]
    top_english = ENGLISH_LETTERS[:5]
    print("\nNajczestsze litery szyfrogramu:", top_cipher)
    print("Najczestsze litery angielskie :", top_english)

    # --- Krok 2: hipotezy i uklad rownan ---
    # Pierwsza hipoteza jest stala: najczestsza litera szyfrogramu to E.
    x1 = letter_to_number(top_english[0])   # E = 4
    y1 = letter_to_number(top_cipher[0])    # np. C = 2

    # Druga hipoteze sprawdzamy dla roznych par (litera jawna -> litera szyfrogramu)
    results = []    # tu zapisujemy poprawne klucze: (score, a, b)
    checked = []    # zeby nie liczyc dwa razy tego samego klucza

    print("\nHIPOTEZY I WYNIKI:")
    print("Hipoteza            a    b    ocena   poczatek tekstu / powod odrzucenia")
    print("-" * 80)

    for cipher_letter in top_cipher[1:]:
        for plain_letter in top_english[1:]:
            x2 = letter_to_number(plain_letter)
            y2 = letter_to_number(cipher_letter)
            label = f"{top_english[0]}->{top_cipher[0]}, {plain_letter}->{cipher_letter}"

            # Odejmujemy rownania:  a*(x1 - x2) = (y1 - y2)  (mod 26)
            possible_a = solve_equation((x1 - x2) % 26, (y1 - y2) % 26)

            for a in possible_a:
                # a musi miec odwrotnosc mod 26, czyli gcd(a, 26) = 1
                if gcd(a, 26) != 1:
                    print(f"{label:<18} {a:>3}    -       -    odrzucony: gcd({a},26) != 1")
                    continue

                # Z pierwszego rownania: b = y1 - a*x1
                b = (y1 - a * x1) % 26

                if (a, b) in checked:
                    continue
                checked.append((a, b))

                plaintext = decrypt(letters, a, b)
                score = score_text(plaintext)
                results.append((score, a, b))
                print(f"{label:<18} {a:>3} {b:>4}   {score:.4f}   {plaintext[:35]}")

    # --- Krok 3: wybor najlepszego klucza ---
    results.sort(reverse=True)          # od najwyzszej oceny
    best_score, a, b = results[0]

    print("\nWYBOR KLUCZA")
    print(f"a = {a}, b = {b}, odwrotnosc a = {modular_inverse(a, 26)}")
    print(f"Ocena: {best_score:.4f} (drugi wynik: {results[1][0]:.4f})")

    print("\nTekst jawny bez spacji:")
    print(decrypt(letters, a, b))
    print("\nTekst jawny ze spacjami:")
    print(" ".join(decrypt(CIPHERTEXT, a, b).split()))


if __name__ == "__main__":
    main()