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


def EncryptBlock(P, round_keys):

    X = []
    
    for i in range(0, len(P), 8):
        X.append(int(P[i:i+8], 16))

    for i in range(28):

        Ki = round_keys[i]

        X0 = l_shift(((X[0] ^ Ki[0]) + (X[1] ^ Ki[1])) & 0xFFFFFFFF, 9)
        X1 = r_shift(((X[1] ^ Ki[2]) + (X[2] ^ Ki[3])) & 0xFFFFFFFF, 5)
        X2 = r_shift(((X[2] ^ Ki[4]) + (X[3] ^ Ki[5])) & 0xFFFFFFFF, 3)
        X3 = X[0]

        X = [X0, X1, X2, X3]

    #return X
    return "".join(f"{i:08x}" for i in X)


def DecryptBlock(C, round_keys):

    X = []

    for i in range(0, len(C), 8):
        X.append(int(C[i:i+8], 16))

    for i in range(27, -1, -1):
        
        Ki = round_keys[i] 
        
        X0 = X[3]
        X1 = ((r_shift(X[0], 9)  - (X0 ^ Ki[0])) & 0xFFFFFFFF) ^ Ki[1]
        X2 = ((l_shift(X[1], 5)  - (X1 ^ Ki[2])) & 0xFFFFFFFF) ^ Ki[3]
        X3 = ((l_shift(X[2], 3)  - (X2 ^ Ki[4])) & 0xFFFFFFFF) ^ Ki[5]
        
        X = [X0, X1, X2, X3]

    #return X
    return "".join(f"{i:08x}" for i in X)


def EncryptData(data, key):

    while len(data)%32 != 0:
        data += '0'
    #print(data)
    blocks = []

    for i in range(0, len(data), 32):
        blocks.append(data[i:i+32])
       
    e_blocks = []
    
    for block in blocks:
        encrypted = EncryptBlock(block, key)
        e_blocks.append(encrypted)
       
    return e_blocks



p =  "23222120272625242b2a29282f2e2d2c"
c = '325eb96f 871bad5a 35f5dc8c f2c67476'

k = "3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b4"
key  = GenerateRoundKeys(k)

data ='23222120272625242b2a29282f2e2d2c23222120272625242b2a29282f2e2d2c'

block = EncryptData(data, key)
print(block)

