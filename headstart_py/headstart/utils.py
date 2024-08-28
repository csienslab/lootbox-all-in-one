import gmpy2
from hashlib import shake_256
from typing import Generator


def H_kgen(x: bytes, k: int) -> Generator[int, None, None]:
    bl = (k + 7) // 8
    M = 1 << k
    while True:
        t = shake_256(x).digest(bl)
        r = int.from_bytes(t, "big")
        r |= 1 << (k - 1)
        yield r % M
        # not really important
        x = t


def H_P(x: bytes, k: int) -> int:
    # hash `x` to a k-bit prime
    for p in H_kgen(x, k):
        p |= 1
        if gmpy2.is_prime(p):
            return p
    raise RuntimeError("unreachable")
