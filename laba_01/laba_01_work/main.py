from functions.cbc import *
from functions.cfb import *
from functions.ecb import *
from functions.gcm import *
from functions.ofb import *


plaintext = "Hello Hello"
key = "secretkey"
iv = "randomiv"
bin_data = b'Hello Hello'

cbc = cbc_encrypt(plaintext, key, iv)
cfb = cfb_encrypt(plaintext, key, iv)
ecb = ecb_encrypt(plaintext, key)
gcm = gcm_encrypt(plaintext, key, iv)
ofb = ofb_encrypt(plaintext, key, iv)

cbc_bytes = cbc_encrypt(bin_data, key, iv)
cfb_bytes = cfb_encrypt(bin_data, key, iv)
ecb_bytes = ecb_encrypt(bin_data, key)
gcm_bytes = gcm_encrypt(bin_data, key, iv)
ofb_bytes = ofb_encrypt(bin_data, key, iv)


def print_table(title, data, is_binary=False):
    print(f"\n{title}\n")
    # Заголовки таблицы
    header = "| {:<8} | {:<80} |".format("Режим", "Зашифрованные данные")
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)

    # Данные для таблицы
    for mode, value in data.items():
        # Если это GCM, выводим кортеж (ciphertext, tag)
        if isinstance(value, tuple):
            value_str = f"({repr(value[0])}, {repr(value[1])})"
        else:
            value_str = repr(value)
        print("| {:<8} | {:<80} |".format(mode, value_str))
    print(separator)


text_data = {
    "CBC": cbc,
    "CFB": cfb,
    "ECB": ecb,
    "GCM": gcm,
    "OFB": ofb
}

binary_data = {
    "CBC": cbc_bytes,
    "CFB": cfb_bytes,
    "ECB": ecb_bytes,
    "GCM": gcm_bytes,
    "OFB": ofb_bytes
}

print_table(f"#1 Шифрование текста - \"{plaintext}\"; Ключ - {key}", text_data)
print_table(f"#2 Шифрование бинарных данных - {bin_data}; Ключ - {key}", binary_data)
