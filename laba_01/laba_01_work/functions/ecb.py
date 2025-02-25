def pad_text(text, block_size):
    """Дополняет текст до длины, кратной block_size"""
    padding_len = block_size - (len(text) % block_size)
    padding = bytes([padding_len] * padding_len)
    return text + padding


def ecb_encrypt(plaintext, key):
    """Шифрование в режиме ECB"""
    block_size = 8
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = key.encode('utf-8')

    if len(key_bytes) < block_size:
        key_bytes = key_bytes + b'\x00' * (block_size - len(key_bytes))
    key_bytes = key_bytes[:block_size]

    padded_text = pad_text(plaintext_bytes, block_size)

    ciphertext = b''
    for i in range(0, len(padded_text), block_size):
        block = padded_text[i:i + block_size]
        encrypted_block = bytes(a ^ b for a, b in zip(block, key_bytes))
        ciphertext += encrypted_block

    return ciphertext

