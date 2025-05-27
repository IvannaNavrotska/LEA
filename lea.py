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


def GenerateRoundKeys(K):
   
    T = []

    for i in range(0, len(K), 8):
        T.append(int(K[i:i+8], 16))
    
    round_keys = []
    
    for i in range(28):
    
        T[0] = l_shift((T[0] + l_shift(delta[i % 6], i)) & 0xFFFFFFFF, 1)
        T[1] = l_shift((T[1] + l_shift(delta[i % 6], i+1)) & 0xFFFFFFFF, 3)
        T[2] = l_shift((T[2] + l_shift(delta[i % 6], i+2)) & 0xFFFFFFFF, 6)
        T[3] = l_shift((T[3] + l_shift(delta[i % 6], i+3)) & 0xFFFFFFFF, 11)
        T[4] = l_shift((T[4] + l_shift(delta[i % 6], i+4)) & 0xFFFFFFFF, 13)
        T[5] = l_shift((T[5] + l_shift(delta[i % 6], i+5)) & 0xFFFFFFFF, 17)
        
        round_keys.append(T[:])  

    return round_keys

k = '3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b4'
round_keys = GenerateRoundKeys(k)

for i, j in enumerate(round_keys):
    print(f"Раунд {i+1:2}:",
          " ".join(hex(x)[2:].zfill(8) for x in j))
