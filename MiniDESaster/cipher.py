from secret import FLAG
from flexDes import *
from binascii import hexlify


key = generate_des_key()
des2 = flexDes(key,mode=ECB, padmode=PAD_PKCS5, rounds=2)
p = f"Yo! Got somethin' coool for ya! Think you can read it? Check this out-- {FLAG}"
c = hexlify(des2.encrypt(p))
with open("output.txt", "w") as f:
    f.write(c.decode())
