from functions.cbc import *
from functions.cfb import *
from functions.ecb import *
from functions.gcm import *
from functions.ofb import *


plaintext = "Hello, my super world!"
key = "secretkey"
iv = "initialiv"

print(f"\nШифрование текста - '{plaintext}'; Ключ - {key}:\n\n ")

cbc = cbc_encrypt(plaintext, key, iv)
cfb = cfb_encrypt(plaintext, key, iv)
ecb = ecb_encrypt(plaintext, key)
gcm = gcm_encrypt(plaintext, key, iv)
ofb = ofb_encrypt(plaintext, key, iv)

print(f"CBC: {cbc}")
print(f"CFB: {cfb}")
print(f"ECB: {ecb}")
print(f"GCM: {gcm}")
print(f"OFB: {ofb}")

