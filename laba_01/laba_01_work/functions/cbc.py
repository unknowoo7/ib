def pad_text(text, block_size):
    """Дополняет текст до длины, кратной block_size"""
    padding_len = block_size - (len(text) % block_size)
    padding = bytes([padding_len] * padding_len)
    return text + padding

def xor_bytes(a, b):
    """Выполняет побитовое XOR двух байтовых строк одинаковой длины"""
    return bytes(x ^ y for x, y in zip(a, b))

def cbc_encrypt(plaintext, key, iv):
    """Шифрование в режиме CBC"""
    block_size = 8
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')
    iv_bytes = iv.encode('utf-8')

    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    key_bytes = key_bytes[:block_size]
    
    if len(iv_bytes) < block_size:
        iv_bytes = iv_bytes + b'\x00' * (block_size - len(iv_bytes))
    iv_bytes = iv_bytes[:block_size]

    padded_text = pad_text(plaintext_bytes, block_size)
    
    ciphertext = b''
    previous_block = iv_bytes

    for i in range(0, len(padded_text), block_size):
        block = padded_text[i:i + block_size]
        block_xor = xor_bytes(block, previous_block)
        encrypted_block = xor_bytes(block_xor, key_bytes)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    
    return ciphertext
