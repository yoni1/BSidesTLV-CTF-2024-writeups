from binascii import unhexlify
from collections import defaultdict
from des import DesKey
from des.core import *

known_plaintext = b"Yo! Got somethin' coool for ya! Think you can read it? Check this out-- "
assert len(known_plaintext) % 8 == 0

ciphertext = unhexlify(open('output.txt', 'r').read())
assert len(ciphertext) % 8 == 0

F_PERMUTATION_INVERSE = [PERMUTATION.index(i) for i in range(32)]

# compute S-box outputs -> possible inputs (4->6)
# list[8] of dict[set]: output->set of inputs
inv_S = []
for box in SUBSTITUTION_BOX:
    inv_box = defaultdict(set)
    for i6 in range(64):
        inv_box[box[i6 & 0x20 | (i6 & 1) << 4 | (i6 & 0x1e) >> 1]].add(i6)
    inv_S.append(inv_box)

# possible values of the two round keys (48-bit), split to eight 6-bit parts
# in the beginning, everything is possible
# (there are key scheduling relations but let's ignore that, hopefully we have enough known plaintext)
k_possibilities = [
    [set(range(64)) for _ in range(8)],
    [set(range(64)) for _ in range(8)]
]

pt_blocks = [known_plaintext[i:i+8] for i in range(0, len(known_plaintext), 8)]
ct_blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]

# go over f-pairs (inputs and outputs to the internal DES function f).
for pt_block, ct_block in zip(pt_blocks, ct_blocks):
    pt_block = permute(int.from_bytes(pt_block, 'big'), 64, INITIAL_PERMUTATION)  # go down: IP
    ct_block = permute(int.from_bytes(ct_block, 'big'), 64, INITIAL_PERMUTATION)  # go up:   IP = FP inverse
    
    L0, R0 = pt_block >> 32, pt_block & 0xffffffff
    R2, L2 = ct_block >> 32, ct_block & 0xffffffff

    # pair for f in round 1: f(R0) = L0 ^ L2
    # pair for f in round 2: f(L2) = R0 ^ R2
    for round_num, f_input, f_output in [(0, R0, L0 ^ L2), (1, L2, R0 ^ R2)]:
        # walk through f from the top down until the S-box inputs
        up_block = permute(f_input, 32, EXPANSION)
        
        # walk through f from the bottom up until the S-box inputs
        down_block = permute(f_output, 32, F_PERMUTATION_INVERSE)

        for box_num in range(8):
            box_output = (down_block >> (28 - box_num*4)) & 0xf
            box_input_before_xor = (up_block >> (42 - box_num*6)) & 0x3f

            # rule out options
            for key_part_option in list(k_possibilities[round_num][box_num]):
                if key_part_option ^ box_input_before_xor not in inv_S[box_num][box_output]:
                    k_possibilities[round_num][box_num].remove(key_part_option)

# Check that we ruled out everything but one option
for round_num in range(2):
    for box_num in range(8):
        assert len(k_possibilities[round_num][box_num]) == 1

# Reconstruct DES round keys
round_keys = []
for key_parts in k_possibilities:
    round_key = 0
    for key_part in key_parts:
        round_key <<= 6
        round_key |= key_part.pop()
    round_keys.append(round_key)

# Decrypt the ciphertext (hack the DesKey object a little bit to do this, we haven't got the original key,
# but we can get by with just the round keys)
des = DesKey(b'AAAAAAAA')
des._DesKey__decryption_key = (tuple(round_keys), )
print(des.decrypt(ciphertext).decode())
# Yo! Got somethin' coool for ya! Think you can read it? Check this out-- BSidesTLV2024{16_r0und5_g1v3_0r_t4k3}
