def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def printable(bs: bytes) -> str:
    # show ASCII; non-printables as dots to eyeball results
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bs)

def crib_drag_attack(guess: str, c1_hex: str, c2_hex: str):
    c1 = bytes.fromhex(c1_hex)          # RAW BYTES, not .decode('ascii')
    c2 = bytes.fromhex(c2_hex)
    x  = xor_bytes(c1, c2)              # Cp1 ⊕ Cp2 = P1 ⊕ P2

    g = guess.encode('ascii', 'ignore') # crib as bytes
    L = len(g)
    if L == 0 or L > len(x):
        print("Crib length invalid for these ciphertexts.")
        return

    for i in range(len(x) - L + 1):
        window = x[i:i+L]               # (P1⊕P2)[i..i+L)
        other  = bytes([window[j] ^ g[j] for j in range(L)])  # reveals P(other)
        print(f"{i:02d}: {printable(other)}")

if __name__ == '__main__':
    ciphertextHex1 = "23000407450a01450d04100b49103115215a451552021d09501b010810161743141c0d541a151a41031a404b"
    ciphertextHex2 = "37091717450d0708160e17434943704468060702094e5e5f434159554746504f55111f02590a1f414b411b5a"

    guess = input("Guess a word: ")
    crib_drag_attack(guess, ciphertextHex1, ciphertextHex2)
