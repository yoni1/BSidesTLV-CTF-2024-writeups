from secret import FLAG
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import binascii


def gen_key(bits):
    N = getPrime(bits)
    e = 65537
    return N, e


def encrypt_message(message, N, e):
    m_int = bytes_to_long(message.encode('utf-8'))
    ciphertext = pow(m_int, e, N)
    return binascii.hexlify(long_to_bytes(ciphertext))


N, e = gen_key(2048)
ciphertext = encrypt_message(FLAG, N, e)

with open('output.txt', 'w') as f:
    f.write(f"{N}\n")
    f.write(ciphertext.decode())
