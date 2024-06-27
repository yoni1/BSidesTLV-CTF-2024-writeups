from hashlib import sha256
from itertools import chain

def calc_dict_xor_diff_vector(dict1, dict2):
    # For the sake of simplicity let's just assume the dicts are simple str->str dicts
    diff = 0
    for k, v in chain(dict1.items(), dict2.items()):
        assert isinstance(k, str)
        assert isinstance(v, str)
        diff ^^= int.from_bytes(sha256(k.encode() + b'\0' + v.encode()).digest(), 'big')
    
    return [(diff >> i) & 1 for i in range(256)]

def gen_vector(k):
    return calc_dict_xor_diff_vector({str(k): str(k)}, {})

def gen_basis():
    k = 0
    basis_ks = []
    basis_vecs = []
    while len(basis_vecs) < 256:
        k += 1
        vec = gen_vector(k)
        basis_vecs.append(vec)
        if matrix(GF(2), basis_vecs).rank() == len(basis_vecs):
            basis_ks.append(k)
        else:
            basis_vecs.pop()
    
    return basis_ks, basis_vecs

def calc_combination(basis_ks, basis_vecs, target_vec):
    # which combination (xor) of basis vectors gives the target vectors?
    M = matrix(GF(2), basis_vecs)
    v = vector(GF(2), target_vec)
    x = M.solve_left(v)
    return [basis_ks[i] for i, b in enumerate(x) if b]

def main():
    diff_vec = calc_dict_xor_diff_vector({"command": "greet"}, {"command": "get_flag"})
    basis_ks, basis_vecs = gen_basis()
    wanted_ks = calc_combination(basis_ks, basis_vecs, diff_vec)
    print({"command": "get_tag", "cmd": "greet", "data": {str(k): str(k) for k in wanted_ks}})

# To run:
# docker run --rm --platform linux/amd64 -v .:/data sagemath/sagemath sage /data/solve.sage
# Output is:
# {'command': 'get_tag', 'cmd': 'greet', 'data': {'3': '3', '5': '5', '6': '6', '7': '7', '10': '10', '11': '11', '12': '12', '13': '13', '16': '16', '18': '18', '19': '19', '22': '22', '25': '25', '27': '27', '29': '29', '31': '31', '34': '34', '35': '35', '36': '36', '39': '39', '41': '41', '45': '45', '47': '47', '48': '48', '53': '53', '54': '54', '55': '55', '60': '60', '61': '61', '63': '63', '65': '65', '68': '68', '69': '69', '76': '76', '79': '79', '80': '80', '81': '81', '83': '83', '84': '84', '85': '85', '87': '87', '88': '88', '90': '90', '91': '91', '92': '92', '94': '94', '97': '97', '98': '98', '99': '99', '100': '100', '101': '101', '102': '102', '106': '106', '107': '107', '109': '109', '110': '110', '112': '112', '115': '115', '116': '116', '118': '118', '119': '119', '122': '122', '124': '124', '127': '127', '128': '128', '129': '129', '130': '130', '135': '135', '136': '136', '138': '138', '139': '139', '140': '140', '141': '141', '144': '144', '147': '147', '148': '148', '149': '149', '153': '153', '156': '156', '160': '160', '162': '162', '163': '163', '165': '165', '169': '169', '171': '171', '173': '173', '174': '174', '178': '178', '181': '181', '183': '183', '186': '186', '188': '188', '191': '191', '193': '193', '198': '198', '199': '199', '202': '202', '204': '204', '205': '205', '206': '206', '209': '209', '210': '210', '212': '212', '214': '214', '215': '215', '216': '216', '219': '219', '221': '221', '225': '225', '229': '229', '232': '232', '233': '233', '234': '234', '235': '235', '237': '237', '239': '239', '242': '242', '251': '251', '252': '252', '254': '254'}}
