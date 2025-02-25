def pad_text(text, block_size):
    """Дополняет текст до длины, кратной block_size"""
    padding_len = block_size - (len(text) % block_size)
    padding = bytes([padding_len] * padding_len)
    return text + padding


def ecb_encrypt(plaintext, key):
    """Шифрование в режиме ECB"""
    block_size = 8  # Размер блока в байтах
    # Преобразуем текст и ключ в байты
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')

    # Убедимся, что ключ соответствует размеру блока
    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    key_bytes = key_bytes[:block_size]  # Обрезаем до block_size, если ключ длиннее

    # Дополняем текст, если нужно
    padded_text = pad_text(plaintext_bytes, block_size)

    ciphertext = b''
    # Шифруем каждый блок
    for i in range(0, len(padded_text), block_size):
        block = padded_text[i:i + block_size]
        # XOR каждого байта блока с байтом ключа
        encrypted_block = bytes(a ^ b for a, b in zip(block, key_bytes))
        ciphertext += encrypted_block

    return ciphertext


def ecb_decrypt(ciphertext, key):
    """Дешифрование в режиме ECB"""
    block_size = 8
    key_bytes = key.encode('utf-8')

    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    key_bytes = key_bytes[:block_size]

    plaintext_bytes = b''
    # Дешифруем каждый блок
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        # XOR с ключом для восстановления исходного текста
        decrypted_block = bytes(a ^ b for a, b in zip(block, key_bytes))
        plaintext_bytes += decrypted_block

    # Удаляем дополнение
    padding_len = plaintext_bytes[-1]
    if padding_len <= block_size:
        plaintext_bytes = plaintext_bytes[:-padding_len]

    return plaintext_bytes.decode('utf-8')


# Пример использования
plaintext = "Hello, ECB mode!"
key = "secretkey"
encrypted = ecb_encrypt(plaintext, key)
#decrypted = ecb_decrypt(encrypted, key)

print(f"Исходный текст: {plaintext}")
print(f"Зашифрованный текст: {encrypted.hex()}")
#print(f"Расшифрованный текст: {decrypted}")
