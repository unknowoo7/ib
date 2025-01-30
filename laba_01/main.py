from Crypto.Cipher import AES
from Crypto.Uсtil.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def generate_key(key_length=16):
    """Генерация ключа (16, 24 или 32 байта для AES-128, AES-192, AES-256)"""
    return get_random_bytes(key_length)


def encrypt_ecb(data, key):
    """
    Шифрование данных в режиме ECB
    Поддерживает текстовые (str) и бинарные (bytes) данные
    Возвращает ciphertext в виде байтов
    """
    # Конвертируем строку в байты при необходимости
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Инициализируем шифр
    cipher = AES.new(key, AES.MODE_ECB)

    # Дополняем данные до размера блока
    padded_data = pad(data, AES.block_size)

    # Шифруем
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def decrypt_ecb(ciphertext, key):
    """Дешифрование данных из режима ECB"""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)


# Пример использования
if __name__ == "__main__":
    # Генерация ключа (16 байт = 128 бит)
    key = generate_key(16)

    # Шифрование текста
    text = "Hello, World!"
    encrypted_text = encrypt_ecb(text, key)
    decrypted_text = decrypt_ecb(encrypted_text, key).decode('utf-8')
    print(f"Text: {decrypted_text}")

    # Шифрование бинарных данных
    binary_data = b'\x01\x02\x03\x04\x05'
    encrypted_bin = encrypt_ecb(binary_data, key)
    decrypted_bin = decrypt_ecb(encrypted_bin, key)
    print(f"Binary: {decrypted_bin}")