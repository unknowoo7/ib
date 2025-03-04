from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os


def generate_keys(key_size=2048):
  key = RSA.generate(key_size)
  private_key = key.export_key()
  public_key = key.publickey().export_key()

  with open("private.pem", "wb") as priv_file:
    priv_file.write(private_key)

  with open("public.pem", "wb") as pub_file:
    pub_file.write(public_key)

  print(f"Ключи {key_size} бит сгенерированы!")


def encrypt_file(file_path, public_key_path="public.pem"):
  with open(file_path, "rb") as file:
    data = file.read()

  with open(public_key_path, "rb") as pub_file:
    public_key = RSA.import_key(pub_file.read())

  cipher = PKCS1_OAEP.new(public_key)
  encrypted_data = cipher.encrypt(data)

  with open(f"{file_path}.txt", "wb") as enc_file:
    enc_file.write(encrypted_data)

  print(f"Файл {file_path} зашифрован!")


def decrypt_file(encrypted_path, private_key_path="private.pem"):
  with open(encrypted_path, "rb") as enc_file:
    encrypted_data = enc_file.read()

  with open(private_key_path, "rb") as priv_file:
    private_key = RSA.import_key(priv_file.read())

  cipher = PKCS1_OAEP.new(private_key)
  decrypted_data = cipher.decrypt(encrypted_data)

  original_path = encrypted_path.replace(".enc", ".dec")
  with open(original_path, "wb") as dec_file:
    dec_file.write(decrypted_data)

  print(f"Файл {encrypted_path} расшифрован в {original_path}!")


# def main():
#     while True:
#         print("\n1. Сгенерировать ключи")
#         print("2. Зашифровать файл")
#         print("3. Расшифровать файл")
#         print("4. Выход")
#         choice = input("Выберите действие: ")
#
#         if choice == "1":
#             size = int(input("Введите размер ключа (1024, 2048, 4096): "))
#             generate_keys(size)
#         elif choice == "2":
#             file_path = input("Введите путь к файлу: ")
#             encrypt_file(file_path)
#         elif choice == "3":
#             file_path = input("Введите путь к зашифрованному файлу: ")
#             decrypt_file(file_path)
#         elif choice == "4":
#             break
#         else:
#             print("Неверный ввод!")


#main()
