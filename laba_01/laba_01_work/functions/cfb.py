def xor_bytes(a, b):
    """Выполняет побитовое XOR двух байтовых строк"""
    return bytes(x ^ y for x, y in zip(a, b))


def cfb_encrypt(plaintext, key, iv, segment_size=1):
    """Шифрование в режиме CFB"""
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

    for i in range(0, len(plaintext_bytes), segment_size):
        encrypted_block = xor_bytes(shift_register, key_bytes)
        plaintext_segment = plaintext_bytes[i:i + segment_size]
        ciphertext_segment = xor_bytes(plaintext_segment, encrypted_block[:segment_size])
        ciphertext += ciphertext_segment

        shift_register = shift_register[segment_size:] + ciphertext_segment
    
    return ciphertext
