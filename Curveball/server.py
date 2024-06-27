import os

from random import randint
from hashlib import sha384
from typing import NamedTuple

class FinitePoint(NamedTuple):
    x: int
    y: int

PointAtInfinity = None

PointType = FinitePoint | PointAtInfinity

class Curve(NamedTuple):
    p: int
    a: int
    b: int
    G: FinitePoint
    n: int
    
    def dbl(self, P: PointType):
        if P is None:
            return PointAtInfinity
        lam = ((3*P.x*P.x+self.a) * pow(2*P.y, -1, self.p)) % self.p
        rx = (lam*lam - 2*P.x) % self.p
        ry = (lam*(P.x-rx) - P.y) % self.p
        return FinitePoint(rx, ry)
    
    def add(self, P: PointType, Q: PointType):
        match P, Q:
            case None, _:
                return Q
            case _, None:
                return P
            case _:
                if P.x == Q.x:
                    if P.y == Q.y:
                        return self.dbl(P)
                    return PointAtInfinity
                lam = ((P.y-Q.y) * pow(P.x-Q.x, -1, self.p)) % self.p
                rx = (lam*lam - P.x - Q.x) % self.p
                ry = (lam*(P.x-rx) - P.y) % self.p
                return FinitePoint(rx, ry)
    
    def mult(self, P: PointType, scalar: int):
        if P is None:
            return PointAtInfinity
        R = PointAtInfinity
        G = P
        s = scalar % self.n
        while s:
            if s&1:
                R = self.add(R, G)
            G = self.dbl(G)
            s >>= 1
        return R
    
    def verify(self, PK: FinitePoint, R: int, S: int, msg: bytes):
        if R <= 0 or S <= 0 or self.n <= R or self.n <= S:
            return False
        Z = int(sha384(msg).hexdigest(), 16)
        Sinv = pow(S, -1, self.n)
        match self.add(self.mult(self.mult(self.G, Sinv), Z), self.mult(self.mult(PK, Sinv), R)):
            case None:
                return False
            case P:
                return P.x == R

BP384 = Curve(
    p=0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
    a=0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826,
    b=0x4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11,
    G=FinitePoint(
        0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e, 
        0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315),
    n=0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565
)

P384 = Curve(
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    a=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    G=FinitePoint(
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
    n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
)


FLAG = os.getenv("FLAG")

def curve_choice():
    print("Curves:")
    print("  1. NIST P-384.")
    print("  2. Brainpool384.")
    curve_choice = int(input("Curve choice > "))
    match curve_choice:
        case 1:
            return P384
        case 2:
            return BP384
        case _:
            raise ValueError(curve_choice)

def coord_choice(curve: Curve, param):
    val = int(input(f'{param}> '), 16)
    assert 0 <= val < curve.p
    return val

def scalar_choice(curve: Curve, param):
    val = int(input(f'{param}> '), 16)
    assert 0 <= val < curve.n
    return val

def main():
    try:
        H = b''
        print("Welcome to curveball.")
        while True:
            action = int(input("Choose action:\n  1. Provision public-key.\n  2. Make a wish.\n > "))
            match action:
                case 1:
                    curve = curve_choice()
                    print("Provisioning public-key from the choosen curve.")
                    x = randint(1, curve.p - 1)
                    # all curve `p` primes are 3 (mod 4)
                    y = pow(pow(x,3, curve.p) + curve.a * x + curve.b,  (curve.p+1)>>2, curve.p)
                    H = sha384(x.to_bytes(48, 'big')+y.to_bytes(48, 'big')).digest()
                    print(f"\tx: {x:096X}")
                    print(f"\ty: {y:096X}")
                    print("Ready.")
                case 2:
                    if H == b'':
                        print("Not provisioned!")
                        continue
                    msg = input("What is your wish? ").encode()
                    print("Provide PK to verify your wish.")
                    curve = curve_choice()
                    x = coord_choice(curve, 'x')
                    y = coord_choice(curve, 'y')
                    assert H == sha384(x.to_bytes(48, 'big')+y.to_bytes(48, 'big')).digest(), "wrong pk hash"
                    print("Provide signature to verify your wish.")
                    R = scalar_choice(curve, 'R')
                    S = scalar_choice(curve, 'S')
                    if curve.verify(FinitePoint(x, y), R, S, msg):
                        print("Wish verified!")
                        if b"I really wanna flag" == msg:
                            print(f"Alright! Alright! {FLAG}")
                        else:
                            print("Why are you here?")
                    else:
                        print("Wish denied!")
                case _:
                    print("Wot?")
    except Exception as e:
        print("Error", e)


if __name__ == "__main__":
    main()
