import unittest
from lea import GenerateRoundKeys128, GenerateRoundKeys192, GenerateRoundKeys256,EncryptBlock, DecryptBlock, EncryptData, DecryptData

class TestLEA(unittest.TestCase):

    def test_for_block_128(self):

        plaintext =  '13121110171615141b1a19181f1e1d1c'
        ciphertext = '354ec89f18c6c628a7c73255fd8b6404'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3'
        key  = GenerateRoundKeys128(k)

        Nr = 24
        
        encrypted = EncryptBlock(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptBlock(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)

        
    def test_for_block_192(self):

        plaintext =  '23222120272625242b2a29282f2e2d2c'
        ciphertext = '325eb96f871bad5a35f5dc8cf2c67476'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b4'
        key  = GenerateRoundKeys192(k)

        Nr = 28
        
        encrypted = EncryptBlock(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptBlock(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)


    def test_for_block_256(self):

        plaintext =  '33323130373635343b3a39383f3e3d3c'
        ciphertext = 'f6af51d6c189b147ca00893a97e1f927'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b44b5a69780f1e2d3c'
        key  = GenerateRoundKeys256(k)

        Nr = 32
        
        encrypted = EncryptBlock(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptBlock(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)

    
    def test_for_data_128(self):

        plaintext =  '13121110171615141b1a19181f1e1d1c13121110171615141b1a19181f1e1d1c'
        ciphertext = '354ec89f18c6c628a7c73255fd8b6404354ec89f18c6c628a7c73255fd8b6404'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3'
        key  = GenerateRoundKeys128(k)

        Nr = 24
        
        encrypted = EncryptData(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptData(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)

        
    def test_encrypt_data_192(self):

        plaintext =  '23222120272625242b2a29282f2e2d2c23222120272625242b2a29282f2e2d2c'
        ciphertext = '325eb96f871bad5a35f5dc8cf2c67476325eb96f871bad5a35f5dc8cf2c67476'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b4'
        key  = GenerateRoundKeys192(k)

        Nr = 28
        
        encrypted = EncryptData(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptData(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_data_256(self):

        plaintext =  '33323130373635343b3a39383f3e3d3c33323130373635343b3a39383f3e3d3c'
        ciphertext = 'f6af51d6c189b147ca00893a97e1f927f6af51d6c189b147ca00893a97e1f927'

        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3c3d2e1f08796a5b44b5a69780f1e2d3c'
        key  = GenerateRoundKeys256(k)

        Nr = 32
        
        encrypted = EncryptData(plaintext, key, Nr)
        self.assertEqual(encrypted, ciphertext)

        decrypted = DecryptData(ciphertext, key, Nr)
        self.assertEqual(decrypted, plaintext)


    def test_decrypt_data_invalid_length(self):

        ciphertext = '354ec89f18c6c628a7c73255fd8b6' #-3 404
        
        k = '3c2d1e0f78695a4bb4a59687f0e1d2c3'
        key  = GenerateRoundKeys128(k)

        Nr = 24

        with self.assertRaises(ValueError) as context:
            DecryptData(ciphertext, key, Nr)

        self.assertIn('Довжина вхідних даних', str(context.exception))

        
if __name__ == '__main__':
    unittest.main()
