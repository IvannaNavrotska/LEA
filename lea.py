def l_shift(x, n):
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def r_shift(x, n):
    n = n % 32
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def GenerateRoundKeys128(K):

    delta = [
        0xc3efe9db,  
        0x44626b02,  
        0x79e27c8a,  
        0x78df30ec]

    T = []
    
    for i in range(0, len(K), 8):
        T.append(int(K[i:i+8], 16))

    round_keys = []

    for i in range(24):
        d = delta[i % 4]
        T[0] = l_shift((T[0] + l_shift(delta[i % 4], i)) & 0xFFFFFFFF, 1)
        T[1] = l_shift((T[1] + l_shift(delta[i % 4], i + 1)) & 0xFFFFFFFF, 3)
        T[2] = l_shift((T[2] + l_shift(delta[i % 4], i + 2)) & 0xFFFFFFFF, 6)
        T[3] = l_shift((T[3] + l_shift(delta[i % 4], i + 3)) & 0xFFFFFFFF, 11)

        Ki = [T[0], T[1], T[2], T[1], T[3], T[1]]
        round_keys.append(Ki)

    return round_keys


def GenerateRoundKeys192(K):

    delta = [
        0xc3efe9db,  
        0x44626b02,  
        0x79e27c8a,  
        0x78df30ec,  
        0x715ea49e,  
        0xc785da0a]
  
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


def GenerateRoundKeys256(K):

    delta = [
        0xc3efe9db,  
        0x44626b02,  
        0x79e27c8a,  
        0x78df30ec,  
        0x715ea49e,  
        0xc785da0a,
        0xe04ef22a,
        0xe5c40957]
  
    T = []

    for i in range(0, len(K), 8):
        T.append(int(K[i:i+8], 16))
    
    round_keys = []
    
    for i in range(32):
    
        T[6*i % 8] = l_shift((T[6*i % 8] + l_shift(delta[i % 8], i)) & 0xFFFFFFFF, 1)
        T[(6*i + 1) % 8] = l_shift((T[(6*i + 1) % 8] + l_shift(delta[i % 8], i+1)) & 0xFFFFFFFF, 3)
        T[(6*i + 2) % 8] = l_shift((T[(6*i + 2) % 8] + l_shift(delta[i % 8], i+2)) & 0xFFFFFFFF, 6)
        T[(6*i + 3) % 8] = l_shift((T[(6*i + 3) % 8] + l_shift(delta[i % 8], i+3)) & 0xFFFFFFFF, 11)
        T[(6*i + 4) % 8] = l_shift((T[(6*i + 4) % 8] + l_shift(delta[i % 8], i+4)) & 0xFFFFFFFF, 13)
        T[(6*i + 5) % 8] = l_shift((T[(6*i + 5) % 8] + l_shift(delta[i % 8], i+5)) & 0xFFFFFFFF, 17)
        
        Ki = [T[6*i % 8], T[(6*i + 1) % 8], T[(6*i + 2) % 8], T[(6*i + 3) % 8], T[(6*i + 4) % 8], T[(6*i + 5) % 8]]
        round_keys.append(Ki)

    return round_keys


def EncryptBlock(P, round_keys, Nr):

    X = []
    
    for i in range(0, len(P), 8):
        X.append(int(P[i:i+8], 16))

    for i in range(Nr):

        Ki = round_keys[i]

        X0 = l_shift(((X[0] ^ Ki[0]) + (X[1] ^ Ki[1])) & 0xFFFFFFFF, 9)
        X1 = r_shift(((X[1] ^ Ki[2]) + (X[2] ^ Ki[3])) & 0xFFFFFFFF, 5)
        X2 = r_shift(((X[2] ^ Ki[4]) + (X[3] ^ Ki[5])) & 0xFFFFFFFF, 3)
        X3 = X[0]

        X = [X0, X1, X2, X3]

    return "".join(f"{i:08x}" for i in X)


def DecryptBlock(C, round_keys, Nr):

    X = []

    for i in range(0, len(C), 8):
        X.append(int(C[i:i+8], 16))

    for i in range(Nr-1, -1, -1):
        
        Ki = round_keys[i] 
        
        X0 = X[3]
        X1 = ((r_shift(X[0], 9)  - (X0 ^ Ki[0])) & 0xFFFFFFFF) ^ Ki[1]
        X2 = ((l_shift(X[1], 5)  - (X1 ^ Ki[2])) & 0xFFFFFFFF) ^ Ki[3]
        X3 = ((l_shift(X[2], 3)  - (X2 ^ Ki[4])) & 0xFFFFFFFF) ^ Ki[5]
        
        X = [X0, X1, X2, X3]

    return "".join(f"{i:08x}" for i in X)


def EncryptData(data, key, Nr):

    while len(data)%32 != 0:
        data += '0'
        
    blocks = []

    for i in range(0, len(data), 32):
        blocks.append(data[i:i+32])
       
    e_blocks = []
    
    for block in blocks:
        encrypted = EncryptBlock(block, key, Nr)
        e_blocks.append(encrypted)

    return "".join(e_blocks)


def DecryptData(data, key, Nr):

    if len(data)%32 != 0:
        raise ValueError('Довжина вхідних даних не поділяється на розмір блоку')
        
    blocks = []
    
    d_blocks = []

    for i in range(0, len(data), 32):
        blocks.append(data[i:i+32])
        
    for block in blocks:
        decrypted = DecryptBlock(block, key, Nr)
        d_blocks.append(decrypted)

    return "".join(d_blocks)
    


