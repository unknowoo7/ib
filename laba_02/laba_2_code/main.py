import random
import base64


def is_prime(n, k=5):
    """ Тест Миллера-Рабина для проверки простоты числа """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    def check(a, d, n, r):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if not check(a, d, n, r):
            return False
    return True


def generate_prime(bits):
    """ Генерация случайного простого числа заданной битности """
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Устанавливаем первый и последний биты (делает число нечётным и достаточной длины)
        if is_prime(num):
            return num


def gcd(a, b):
    """ Нахождение наибольшего общего делителя (НОД) """
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """ Нахождение мультипликативного обратного числа d к e по модулю phi (Расширенный алгоритм Евклида) """
    a, b, u = 0, phi, 1
    while e > 0:
        q = b // e
        e, a, b, u = b % e, u, e, a - q * u
    if b == 1:
        return a % phi


def generate_keys(key_size):
    """ Генерация открытого и закрытого ключей """
    print(f"Генерация {key_size}-битного ключа...")

    bit_length = key_size // 2
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Чаще всего используется это значение
    while gcd(e, phi) != 1:  # Проверяем, что e взаимно просто с phi
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def encrypt(message, public_key):
    """ Шифрование сообщения с помощью открытого ключа """
    e, n = public_key
    cipher_text = [pow(ord(char), e, n) for char in message]
    return cipher_text


def decrypt(cipher_text, private_key):
    """ Дешифрование сообщения с помощью закрытого ключа """
    d, n = private_key
    message = ''.join(chr(pow(char, d, n)) for char in cipher_text)
    return message


def encrypt_file(file_path, public_key):
    with open(file_path, "rb") as file:
        data = file.read()
        data_str = base64.b64encode(data).decode()
        encrypted_data = encrypt(data_str, public_key)

    with open(f"e_{file_path}", "w") as enc_file:
        enc_file.write(" ".join(map(str, encrypted_data)))

    print(f"Файл e_{file_path} зашифрован!")


def decrypt_file(file_path, private_key):
    with open(f"{file_path}", "r") as file:
        encrypted_data = list(map(int, file.read().split()))

    decrypted_str = decrypt(encrypted_data, private_key)  # Дешифруем строку
    original_data = base64.b64decode(decrypted_str).decode()  # Декодируем из base64 в байты

    print(f"{original_data}")


def main():
    key_size = 1024
    public_key, private_key = generate_keys(key_size)

    while True:
        print("\n1. Сгенерировать ключи")
        print("2. Зашифровать файл")
        print("3. Расшифровать файл")
        print("4. Выход")
        choice = input("Выберите действие: ")

        if choice == "1":
            key_size = int(input("Введите размер ключа (1024, 2048, 4096): "))
        elif choice == "2":
            file_path = input("Введите путь к файлу: ")
            print(f"{file_path}")
            encrypt_file(file_path, public_key)
        elif choice == "3":
            file_path = input("Введите путь к зашифрованному файлу: ")
            decrypt_file(file_path, private_key)
        elif choice == "4":
            break
        else:
            print("Неверный ввод!")


if __name__ == "__main__":
    main()
