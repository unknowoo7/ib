def xor_bytes(a, b):
    """Выполняет побитовое XOR двух байтовых строк"""
    return bytes(x ^ y for x, y in zip(a, b))

def inc_counter(counter):
    """Увеличивает 32-битный счётчик в конце блока"""
    counter_int = int.from_bytes(counter[-4:], 'big')
    counter_int = (counter_int + 1) & 0xFFFFFFFF  # Ограничиваем 32 битами
    return counter[:-4] + counter_int.to_bytes(4, 'big')

def ghash(h, data):
    """Упрощённая имитация GHASH (XOR вместо умножения в поле Галуа)"""
    block_size = 16
    result = bytes(block_size)

    if len(data) % block_size != 0:
        data += b'\x00' * (block_size - len(data) % block_size)

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        result = xor_bytes(result, block)
    
    return xor_bytes(result, h)

def gcm_encrypt(plaintext, key, iv, aad=b''):
    """Шифрование в режиме GCM"""
    block_size = 16
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    key_bytes = key_bytes[:block_size]

    if len(iv_bytes) != 12:
        iv_bytes = iv_bytes.ljust(12, b'\x00')[:12]
    counter = iv_bytes + b'\x00\x00\x00\x01'

    h = xor_bytes(bytes(block_size), key_bytes)
    
    ciphertext = b''
    for i in range(0, len(plaintext_bytes), block_size):
        keystream = xor_bytes(counter, key_bytes)
        plaintext_block = plaintext_bytes[i:i + block_size]
        ciphertext_block = xor_bytes(plaintext_block, keystream[:len(plaintext_block)])
        ciphertext += ciphertext_block
        counter = inc_counter(counter)

    len_aad = len(aad) * 8
    len_ciphertext = len(ciphertext) * 8
    auth_data = aad + ciphertext + len_aad.to_bytes(8, 'big') + len_ciphertext.to_bytes(8, 'big')
    tag = ghash(h, auth_data)
    
    return ciphertext, tag
