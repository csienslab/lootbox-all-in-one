from gmpy2 import mpz, gcd, gcdext


def solve_linmod(a, b, m):
    # solve ax = b (mod m)
    # return u, v such that x = u + v * n

    g, d, e = gcdext(a, m)
    q = b // g
    r = b % g
    if r != 0:
        raise ValueError("no solution")
    u = q * d % m
    v = m // g
    return u, v


class BinaryQF:
    def __init__(self, a: int, b: int, c: int):
        self.a = mpz(a)
        self.b = mpz(b)
        self.c = mpz(c)

    def __repr__(self):
        return f"{self.a}x^2 + {self.b}xy + {self.c}y^2"

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.c == other.c

    def __iter__(self):
        yield self.a
        yield self.b
        yield self.c

    def discriminant(self):
        return self.b**2 - 4 * self.a * self.c

    def __mul__(self, other):
        if self == other:
            return self.square()
        # gaussian composition
        a, b, c = self.a, self.b, self.c
        α, β, γ = other.a, other.b, other.c
        g = (b + β) // 2
        h = -(b - β) // 2
        w = gcd(gcd(a, α), g)
        j = w
        s = a // w
        t = α // w
        u = g // w
        µ, ν = solve_linmod(t * u, h * u + s * c, s * t)
        λ = solve_linmod(t * ν, h - t * µ, s)[0]
        k = µ + ν * λ
        l = (k * t - h) // s
        m = (t * u * k - h * u - c * s) // (s * t)
        A = s * t
        B = j * u - (k * t + l * s)
        C = k * l - j * m
        return BinaryQF(A, B, C)

    def square(self):
        a, b, c = self.a, self.b, self.c
        mu = solve_linmod(b, c, a)[0]
        A = a**2
        B = b - 2 * a * mu
        C = mu**2 - (b * mu - c) // a
        return BinaryQF(A, B, C)

    def normalize(self):
        a, b, c = self.a, self.b, self.c
        r = (a - b) // (2 * a)
        A = a
        B = b + 2 * r * a
        C = a * r * r + b * r + c
        return BinaryQF(A, B, C)

    def reduced_form(self):
        nf = self.normalize()
        a, b, c = nf.a, nf.b, nf.c
        while not (a < c or (a == c and b >= 0)):
            s = (c + b) // (2 * c)
            A = c
            B = -b + 2 * s * c
            C = c * s * s - b * s + a
            a, b, c = A, B, C
        return BinaryQF(a, b, c)


def get_qf_principal_form(d: int) -> BinaryQF:
    # get the principal form of discriminant `d`
    # aka identity element
    # from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf Definition 5.4
    k = d % 2
    return BinaryQF(1, k, (k**2 - d) // 4)


def qf_pow(x: BinaryQF, n: int) -> BinaryQF:
    r = get_qf_principal_form(x.discriminant())
    while n > 0:
        if n & 1:
            r = (r * x).reduced_form()
        x *= x
        n >>= 1
        x = x.reduced_form()
    return r


def qf_tobytes(x: BinaryQF, b: int) -> bytes:
    r = b""
    for v in x:
        r += int(v).to_bytes(b // 8, "big", signed=True)
    return r


def qf_frombytes(x: bytes, b: int) -> BinaryQF:
    r = []
    for i in range(0, len(x), b // 8):
        v = int.from_bytes(x[i : i + b // 8], "big", signed=True)
        r.append(v)
    return BinaryQF(*r)


if __name__ == "__main__":
    x = BinaryQF(12, 23, 34)
    print(x.reduced_form())
    print((x * x).reduced_form())
    print((x * x * x).reduced_form())

    from sage.all import BinaryQF as SageBinaryQF

    x = SageBinaryQF(12, 23, 34)
    print(x.reduced_form())
    print((x * x).reduced_form())
    print((x * x * x).reduced_form())
