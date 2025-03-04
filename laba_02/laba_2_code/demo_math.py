import random


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


# Тестирование
key_size = 1024  # Можно выбрать 2048 или 4096
public_key, private_key = generate_keys(key_size)

print(f"\nПубличный ключ: {public_key}")
print(f"Приватный ключ: {private_key}")

message = "Hello, RSA!"
print(f"\nИсходное сообщение: {message}")

encrypted_msg = encrypt(message, public_key)
print(f"\nЗашифрованное сообщение: {encrypted_msg}")

decrypted_msg = decrypt(encrypted_msg, private_key)
print(f"\nРасшифрованное сообщение: {decrypted_msg}")

