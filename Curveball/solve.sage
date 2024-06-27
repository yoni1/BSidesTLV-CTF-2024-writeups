# Run with:
# docker run --rm --platform linux/amd64 -v .:/data sagemath/sagemath "pip install pwntools && sage /data/solve.sage"

from pwn import *
from hashlib import sha384
from server import P384

MSG_TO_SIGN = b"I really wanna flag"
Z_TO_SIGN = int(sha384(MSG_TO_SIGN).hexdigest(), 16)

server = remote("0.cloud.chals.io", 26217)

def get_public_key(curve_id):
    server.recvuntil(b'\n > ')
    server.sendline(b'1')
    server.recvuntil(b'Curve choice > ')
    server.sendline(str(curve_id).encode())
    server.recvuntil(b'x: ')
    x = server.recvline()
    server.recvuntil(b'y: ')
    y = server.recvline()

    x = int(x.decode().strip(), 16)
    y = int(y.decode().strip(), 16)
    return x, y

def get_flag(curve_id, x, y, r, s):
    server.recvuntil(b'\n > ')
    server.sendline(b'2')
    server.recvuntil(b'What is your wish? ')
    server.sendline(MSG_TO_SIGN)
    server.recvuntil(b'Curve choice > ')
    server.sendline(str(curve_id).encode())

    for param, value in (('x', x), ('y', y), ('R', r), ('S', s)):
        server.recvuntil(f'{param}> '.encode())
        server.sendline(hex(value)[2:].encode())

    assert server.recvline() == b'Wish verified!\n'
    return server.recvline().decode().strip()


# The ECDSA verification calculation is:
# (x1, y1) = (z/s)G + (r/s)Q
# Where z = hash(msg), r and s are given by us, G is constant and Q is the public key.
# In the server code it is done like this:
# self.add(self.mult(self.mult(self.G, Sinv), Z), self.mult(self.mult(PK, Sinv), R))
# Note that Q ("PK") is multiplied first by Sinv and then by R (I'm not sure the order matters too much though).
#
# What happens if Q falls off the curve?
# It then simply belongs to a different elliptic curve, where a is the same and b is different.
# The reason is that mult() and add() are implemented with regard to the points' coordinates,
# and the "a" parameter of the curve, but NOT the "b" parameter.
# So any point in space determines a curve by choosing "b".
#
# If we are lucky and Q belongs to a curve of order less than n, then we can set s = 1/(order of that curve) mod n.
# What then happens is that Sinv = order of that curve, and Sinv * Q = point at infinity.
# Then (x1, y1) = (z/s)G only, and we can simply set r to be the x coordinate of that point and pass the verification.

E_P384 = EllipticCurve(GF(P384.p), [P384.a, P384.b])
G_P384 = E_P384(P384.G.x, P384.G.y)

attempt_num = 1
while True:
    info(f'Attempt {attempt_num}')
    info('Getting public key from BP384')
    x, y = get_public_key(2)
    
    info('Finding alternative P384-like curve for this public key')
    # y^2 = x^3 + ax + b    --->    b = y^2 - x^3 - ax
    b = (pow(y, 2, P384.p) - pow(x, 3, P384.p) - P384.a * x) % P384.p
    E_alt = EllipticCurve(GF(P384.p), [P384.a, b])

    info('Calculating group order... This will take a moment')
    nn = E_alt.order()

    if nn < P384.n:
        info('Found group of smaller order!')
        break
    else:
        info('No luck, trying again.')
        attempt_num += 1

# Forge signature
s = int(pow(nn, -1, P384.n))
verification_point = Z_TO_SIGN * (nn * G_P384)
r = int(verification_point.x())

info('Getting flag...')
info(get_flag(1, x, y, r, s))
# BSidesTLV2024{7h3_P01n7_47_1nf1n1ty_15_y0ur_curvy_fr13nd?}
