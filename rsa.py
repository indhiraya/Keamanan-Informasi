import random
import secrets

def modexp(a, e, n):
    result = 1
    a = a % n
    while e > 0:
        if e & 1:
            result = (result * a) % n
        a = (a * a) % n
        e >>= 1
    return result

def is_prime_miller_rabin(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def rand_bits(bits):
    n = secrets.randbits(bits)
    n |= (1 << (bits - 1)) | 1
    return n

def generate_large_prime(bits=512):
    while True:
        candidate = rand_bits(bits)
        if is_prime_miller_rabin(candidate, k=12):
            return candidate

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (g, x, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % m

def generate_rsa_keypair(bits=1024):
    half = bits // 2
    p = generate_large_prime(half)
    q = generate_large_prime(half)
    while q == p:
        q = generate_large_prime(half)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if phi % e == 0:
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2
    d = modinv(e, phi)
    pub = (e, n)
    priv = (d, n)
    return pub, priv

def rsa_encrypt(m, pubkey):
    e, n = pubkey
    if m >= n:
        raise ValueError("message too large for modulus")
    return modexp(m, e, n)

def rsa_decrypt(c, privkey):
    d, n = privkey
    return modexp(c, d, n)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b'\x00'
    blen = (n.bit_length() + 7) // 8
    return n.to_bytes(blen, byteorder='big')

def rsa_sign_int(msg_int: int, privkey):
    d, n = privkey
    return modexp(msg_int, d, n)

def rsa_verify_int(sig_int: int, pubkey):
    e, n = pubkey
    return modexp(sig_int, e, n)