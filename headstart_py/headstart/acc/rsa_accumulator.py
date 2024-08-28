from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import gmpy2, math
from headstart.utils import H_P
from headstart.abstract import AbstractAccumulator, AbstractUniversalAccumulator


class RSAAccumulator(AbstractAccumulator[int, int, int]):
    def __init__(self, n: int, g: int):
        self.n = gmpy2.mpz(n)
        self.g = gmpy2.mpz(g)
        self.witness_cache = {}

    def bytes_to_long(self, x):
        return int.from_bytes(x, "big")

    def accumulate(self, X: list[bytes]) -> int:
        r = self.g
        for x in X:
            r = gmpy2.powmod(r, self.bytes_to_long(x), self.n)
        return int(r)

    def batch_witgen(self, X: list[bytes]) -> list[int]:
        def root_factor(g, X):
            if len(X) == 1:
                return [g]
            h = len(X) // 2
            gl = g
            for x in X[:h]:
                gl = gmpy2.powmod(gl, self.bytes_to_long(x), self.n)
            gr = g
            for x in X[h:]:
                gr = gmpy2.powmod(gr, self.bytes_to_long(x), self.n)
            L = root_factor(gr, X[:h])
            R = root_factor(gl, X[h:])
            return L + R

        return root_factor(self.g, X)

    def witgen(self, acc: int, X: list[bytes], index: int) -> int:
        cache_key = hash(tuple(X))
        if cache_key not in self.witness_cache:
            self.witness_cache[cache_key] = self.batch_witgen(X)
        witness_cache = self.witness_cache[cache_key]
        return witness_cache[index]

    def verify(self, acc: int, w: int, x: bytes) -> bool:
        return gmpy2.powmod(w, self.bytes_to_long(x), self.n) == acc

    def get_accval(self, acc: int) -> int:
        return acc

    def get_bytes(self, acc: int) -> bytes:
        bl = (self.n.bit_length() + 7) // 8
        return acc.to_bytes(bl, "big")

    @classmethod
    def generate(cls, bits):
        # require trusted setup :(
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        g = pow(2, 65537, n)
        return cls(n, g)


class RSAPrimeAccumulator(
    RSAAccumulator, AbstractUniversalAccumulator[int, int, int, tuple[int, int]]
):
    def bytes_to_long(self, x):
        return H_P(x, 256)

    def nonmemwitgen(self, acc: int, X: list[bytes], x: bytes) -> tuple[int, int]:
        s = math.prod(self.bytes_to_long(x) for x in X)
        _, a, b = gmpy2.gcdext(s, self.bytes_to_long(x))
        B = gmpy2.powmod(self.g, b, self.n)
        return a, B

    def nonmemverify(self, acc: int, w: tuple[int, int], x: bytes) -> bool:
        a, B = w
        return (
            gmpy2.powmod(acc, a, self.n)
            * gmpy2.powmod(B, self.bytes_to_long(x), self.n)
            % self.n
            == self.g
        )


if __name__ == "__main__":
    acc = RSAAccumulator.generate(1024)
    X = [b"peko", b"peko2", b"peko3"]
    accm = acc.accumulate(X)
    w = acc.witgen(accm, X, 1)
    accval = acc.get_accval(accm)
    assert acc.verify(accval, w, X[1])
    print(acc.get_bytes(accval))

    ww = acc.batch_witgen(X)
    for x, w in zip(X, ww):
        assert acc.verify(accval, w, x)

    acc2 = RSAPrimeAccumulator.generate(1024)
    X = [b"peko", b"peko2", b"peko3"]
    accm = acc2.accumulate(X)
    w = acc2.witgen(accm, X, 1)
    accval = acc2.get_accval(accm)
    assert acc2.verify(accval, w, X[1])
    print(acc2.get_bytes(accval))
    w = acc2.nonmemwitgen(accm, X, b"peko4")
    assert acc2.nonmemverify(accval, w, b"peko4")
    w = acc2.nonmemwitgen(accm, X, X[0])
    assert not acc2.nonmemverify(accval, w, X[0])
