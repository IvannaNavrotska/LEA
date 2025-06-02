from lea import GenerateRoundKeys128, GenerateRoundKeys192, GenerateRoundKeys256, EncryptData, DecryptData

def open_file(path):
    with open(path, 'r') as f:
        return f.read().strip()

def create_file(path, data):
    with open(path, 'w') as f:
        f.write(data)


def round_keys(key, size):
    
    if size == 128:
        return GenerateRoundKeys128(key), 24
    
    elif size == 192:
        return GenerateRoundKeys192(key), 28
    
    elif size == 256:
        return GenerateRoundKeys256(key), 32
    else:
        raise ValueError('Ключ повинен бути 128, 192 або 256 біт')


def for_user():
    
    print('Вас вітає LEA')
    
    enc_or_dec = input('Будемо шифрувати чи розшифровувати(encrypt/decrypt): ').strip().lower()

    input_file = input('Введіть назву вхідного файла: ').strip()
    output_file = input('Введіть назву файла для результату: ').strip()
    key_file = input('Введіть назву файла з ключем: ').strip()
    keysize = int(input('Введіть розмір ключа (128 / 192 / 256): ').strip())

    try:
        data = open_file(input_file)
        key_data = open_file(key_file)
        key, Nr = round_keys(key_data, keysize)

        if enc_or_dec == 'encrypt':
            result = EncryptData(data, key, Nr)
        elif enc_or_dec == 'decrypt':
            result = DecryptData(data, key, Nr)
        else:
            print('Лише шифруємо та розшифровуємо')
            return

        create_file(output_file, result)
        print(f'Результат записано у: {output_file}')

    except Exception as e:
        print(f'Щось пішло не так: {e}')

for_user()
