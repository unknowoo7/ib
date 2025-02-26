def xor_bytes(a, b):
    """Побитовое XOR двух байтовых строк"""
    return bytes(x ^ y for x, y in zip(a, b))


def pad_text(data, block_size):
    """Дополнение данных до кратности block_size"""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def fake_aes_encrypt(block, key):
    """Упрощённая имитация AES (XOR с ключом)"""
    if len(key) < len(block):
        key = (key * (len(block) // len(key) + 1))[:len(block)]
    return xor_bytes(block, key)


# ECB (Electronic Codebook)
def ecb_encrypt(data, key):
    block_size = 16
    padded_data = pad_text(data, block_size)
    ciphertext = b''
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i + block_size]
        encrypted_block = fake_aes_encrypt(block, key)
        ciphertext += encrypted_block
    return ciphertext


def ecb_decrypt(ciphertext, key):
    block_size = 16
    plaintext = b''
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = fake_aes_encrypt(block, key)  # XOR обратим
        plaintext += decrypted_block
    padding_len = plaintext[-1]
    return plaintext[:-padding_len]


# CBC (Cipher Block Chaining)
def cbc_encrypt(data, key, iv):
    block_size = 16
    padded_data = pad_text(data, block_size)
    ciphertext = b''
    previous_block = iv
    for i in range(0, len(padded_data), block_size):
        block = padded_data[i:i + block_size]
        block_xor = xor_bytes(block, previous_block)
        encrypted_block = fake_aes_encrypt(block_xor, key)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    block_size = 16
    plaintext = b''
    previous_block = iv
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = fake_aes_encrypt(block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        plaintext += plaintext_block
        previous_block = block
    padding_len = plaintext[-1]
    return plaintext[:-padding_len]


# CFB (Cipher Feedback)
def cfb_encrypt(data, key, iv, segment_size=1):
    block_size = 16
    ciphertext = b''
    shift_register = iv
    for i in range(0, len(data), segment_size):
        keystream = fake_aes_encrypt(shift_register, key)
        plaintext_segment = data[i:i + segment_size]
        ciphertext_segment = xor_bytes(plaintext_segment, keystream[:segment_size])
        ciphertext += ciphertext_segment
        shift_register = shift_register[segment_size:] + ciphertext_segment
    return ciphertext


def cfb_decrypt(ciphertext, key, iv, segment_size=1):
    block_size = 16
    plaintext = b''
    shift_register = iv
    for i in range(0, len(ciphertext), segment_size):
        keystream = fake_aes_encrypt(shift_register, key)
        ciphertext_segment = ciphertext[i:i + segment_size]
        plaintext_segment = xor_bytes(ciphertext_segment, keystream[:segment_size])
        plaintext += plaintext_segment
        shift_register = shift_register[segment_size:] + ciphertext_segment
    return plaintext


# OFB (Output Feedback)
def ofb_encrypt(data, key, iv):
    block_size = 16
    ciphertext = b''
    shift_register = iv
    for i in range(0, len(data), block_size):
        keystream = fake_aes_encrypt(shift_register, key)
        plaintext_segment = data[i:i + block_size]
        ciphertext_segment = xor_bytes(plaintext_segment, keystream[:len(plaintext_segment)])
        ciphertext += ciphertext_segment
        shift_register = keystream
    return ciphertext


def ofb_decrypt(ciphertext, key, iv):
    return ofb_encrypt(ciphertext, key, iv)  # OFB симметричен


# GCM (Galois/Counter Mode)
def inc_counter(counter):
    counter_int = int.from_bytes(counter[-4:], 'big')
    counter_int = (counter_int + 1) & 0xFFFFFFFF
    return counter[:-4] + counter_int.to_bytes(4, 'big')


def ghash(h, data):  # Упрощённый GHASH
    block_size = 16
    result = bytes(block_size)
    if len(data) % block_size != 0:
        data += b'\x00' * (block_size - len(data) % block_size)
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        result = xor_bytes(result, block)
    return xor_bytes(result, h)


def gcm_encrypt(data, key, iv, aad=b''):
    block_size = 16
    if len(iv) != 12:
        iv = iv.ljust(12, b'\x00')[:12]
    counter = iv + b'\x00\x00\x00\x01'
    h = fake_aes_encrypt(bytes(block_size), key)

    ciphertext = b''
    for i in range(0, len(data), block_size):
        keystream = fake_aes_encrypt(counter, key)
        plaintext_block = data[i:i + block_size]
        ciphertext_block = xor_bytes(plaintext_block, keystream[:len(plaintext_block)])
        ciphertext += ciphertext_block
        counter = inc_counter(counter)

    len_aad = len(aad) * 8
    len_ciphertext = len(ciphertext) * 8
    auth_data = aad + ciphertext + len_aad.to_bytes(8, 'big') + len_ciphertext.to_bytes(8, 'big')
    tag = ghash(h, auth_data)
    return ciphertext, tag


def gcm_decrypt(ciphertext, key, iv, aad, tag):
    block_size = 16
    if len(iv) != 12:
        iv = iv.ljust(12, b'\x00')[:12]
    counter = iv + b'\x00\x00\x00\x01'
    h = fake_aes_encrypt(bytes(block_size), key)

    plaintext = b''
    for i in range(0, len(ciphertext), block_size):
        keystream = fake_aes_encrypt(counter, key)
        ciphertext_block = ciphertext[i:i + block_size]
        plaintext_block = xor_bytes(ciphertext_block, keystream[:len(ciphertext_block)])
        plaintext += plaintext_block
        counter = inc_counter(counter)

    len_aad = len(aad) * 8
    len_ciphertext = len(ciphertext) * 8
    auth_data = aad + ciphertext + len_aad.to_bytes(8, 'big') + len_ciphertext.to_bytes(8, 'big')
    computed_tag = ghash(h, auth_data)
    if computed_tag != tag:
        raise ValueError("Тег аутентификации не совпадает")
    return plaintext


# Тест и сравнение
def test_modes():
    key = b"secretkey1234567"  # 16 байт
    iv = b"initialiv123"  # 12 байт для GCM, дополним для других
    aad = b"authdata"

    # Текстовые данные
    text_data = b"This is a test message for AES modes!"
    print("=== Текстовые данные ===")
    print(f"Исходный текст: {text_data.decode('utf-8')}")

    # Бинарные данные (например, случайные байты)
    binary_data = bytes([0x41, 0x42, 0x43, 0x00, 0xFF, 0xEE, 0xDD, 0xCC])
    print("\n=== Бинарные данные ===")
    print(f"Исходные байты: {binary_data.hex()}")

    # ECB
    ecb_enc_text = ecb_encrypt(text_data, key)
    ecb_dec_text = ecb_decrypt(ecb_enc_text, key)
    ecb_enc_bin = ecb_encrypt(binary_data, key)
    ecb_dec_bin = ecb_decrypt(ecb_enc_bin, key)
    print("\nECB:")
    print(f"Текст зашифрован: {ecb_enc_text.hex()} | Расшифрован: {ecb_dec_text.decode('utf-8')}")
    print(f"Бинарный зашифрован: {ecb_enc_bin.hex()} | Расшифрован: {ecb_dec_bin.hex()}")

    # CBC
    cbc_enc_text = cbc_encrypt(text_data, key, iv)
    cbc_dec_text = cbc_decrypt(cbc_enc_text, key, iv)
    cbc_enc_bin = cbc_encrypt(binary_data, key, iv)
    cbc_dec_bin = cbc_decrypt(cbc_enc_bin, key, iv)
    print("\nCBC:")
    print(f"Текст зашифрован: {cbc_enc_text.hex()} | Расшифрован: {cbc_dec_text.decode('utf-8')}")
    print(f"Бинарный зашифрован: {cbc_enc_bin.hex()} | Расшифрован: {cbc_dec_bin.hex()}")

    # CFB
    cfb_enc_text = cfb_encrypt(text_data, key, iv)
    cfb_dec_text = cfb_decrypt(cfb_enc_text, key, iv)
    cfb_enc_bin = cfb_encrypt(binary_data, key, iv)
    cfb_dec_bin = cfb_decrypt(cfb_enc_bin, key, iv)
    print("\nCFB:")
    print(f"Текст зашифрован: {cfb_enc_text.hex()} | Расшифрован: {cfb_dec_text.decode('utf-8')}")
    print(f"Бинарный зашифрован: {cfb_enc_bin.hex()} | Расшифрован: {cfb_dec_bin.hex()}")

    # OFB
    ofb_enc_text = ofb_encrypt(text_data, key, iv)
    ofb_dec_text = ofb_decrypt(ofb_enc_text, key, iv)
    ofb_enc_bin = ofb_encrypt(binary_data, key, iv)
    ofb_dec_bin = ofb_decrypt(ofb_enc_bin, key, iv)
    print("\nOFB:")
    print(f"Текст зашифрован: {ofb_enc_text.hex()} | Расшифрован: {ofb_dec_text.decode('utf-8')}")
    print(f"Бинарный зашифрован: {ofb_enc_bin.hex()} | Расшифрован: {ofb_dec_bin.hex()}")

    # GCM
    gcm_enc_text, gcm_tag_text = gcm_encrypt(text_data, key, iv, aad)
    gcm_dec_text = gcm_decrypt(gcm_enc_text, key, iv, aad, gcm_tag_text)
    gcm_enc_bin, gcm_tag_bin = gcm_encrypt(binary_data, key, iv, aad)
    gcm_dec_bin = gcm_decrypt(gcm_enc_bin, key, iv, aad, gcm_tag_bin)
    print("\nGCM:")
    print(
        f"Текст зашифрован: {gcm_enc_text.hex()} | Тег: {gcm_tag_text.hex()} | Расшифрован: {gcm_dec_text.decode('utf-8')}")
    print(f"Бинарный зашифрован: {gcm_enc_bin.hex()} | Тег: {gcm_tag_bin.hex()} | Расшифрован: {gcm_dec_bin.hex()}")


if __name__ == "__main__":
    test_modes()