def xor_bytes(a, b):
    """Выполняет побитовое XOR двух байтовых строк"""
    return bytes(x ^ y for x, y in zip(a, b))

def ofb_encrypt(plaintext, key, iv):
    """Шифрование в режиме OFB"""
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
    
    ciphertext = b''
    shift_register = iv_bytes

    for i in range(len(plaintext_bytes)):
        keystream_block = xor_bytes(shift_register, key_bytes)
        plaintext_byte = plaintext_bytes[i:i + 1]
        ciphertext_byte = xor_bytes(plaintext_byte, keystream_block[:1])
        ciphertext += ciphertext_byte

        shift_register = keystream_block
    
    return ciphertext
