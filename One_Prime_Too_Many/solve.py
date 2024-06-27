from binascii import unhexlify

n, c = open("output.txt", "r").readlines()
n = int(n)
c = int(c, 16)
# oops, n is prime, phi(n) = n - 1, so e is trivial to invert
d = pow(65537, -1, n - 1)
m = pow(c, d, n)
print(unhexlify(hex(m)[2:]).decode())
# BSidesTLV2024{wh0_g4v3_u_pr1m3_N?}
