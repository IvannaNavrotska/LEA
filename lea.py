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


if __name__ == "__main__":
    
    key =  "3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b4"
    p  =  "23222120272625242b2a29282f2e2d2c"

    k  = GenerateRoundKeys(key)
    c  = EncryptBlock(p, k)

    print("cipher =", c)
