delta = [
    0xc3efe9db,  
    0x44626b02,  
    0x79e27c8a,  
    0x78df30ec,  
    0x715ea49e,  
    0xc785da0a]


def l_shift(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def r_shift(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

