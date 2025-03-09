#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>

using namespace std;

// Побитовые операции для SHA-1
#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

// Функция для дополнения исходного сообщения
vector<uint8_t> padMessage(const string& message) {
    vector<uint8_t> paddedMessage(message.begin(), message.end());

    // Добавляем 1 бит (0x80)
    paddedMessage.push_back(0x80);

    // Вычисляем необходимый размер дополнения
    size_t originalBitLength = message.size() * 8;
    while ((paddedMessage.size() * 8) % 512 != 448) {
        paddedMessage.push_back(0x00);
    }

    // Добавляем исходную длину сообщения в битах (64-битное представление)
    for (int i = 7; i >= 0; i--) {
        paddedMessage.push_back(static_cast<uint8_t>((originalBitLength >> (i * 8)) & 0xFF));
    }

    return paddedMessage;
}

// Основная функция SHA-1
string sha1(const string& message) {
    // Инициализируем буфер
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Подготовка данных
    vector<uint8_t> paddedMessage = padMessage(message);

    // Разбиваем на 512-битные блоки
    for (size_t chunk = 0; chunk < paddedMessage.size(); chunk += 64) {
        uint32_t w[80] = { 0 };

        // Загружаем 16 слов по 32 бита
        for (int i = 0; i < 16; i++) {
            w[i] = (paddedMessage[chunk + i * 4] << 24) |
                (paddedMessage[chunk + i * 4 + 1] << 16) |
                (paddedMessage[chunk + i * 4 + 2] << 8) |
                (paddedMessage[chunk + i * 4 + 3]);
        }

        // Генерация оставшихся 64 слов
        for (int i = 16; i < 80; i++) {
            w[i] = ROTLEFT((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
        }

        // Инициализация переменных для этого блока
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // Основной цикл SHA-1
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;

            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = ROTLEFT(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = ROTLEFT(b, 30);
            b = a;
            a = temp;
        }

        // Обновляем итоговые значения
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // Формируем строку хэша
    stringstream ss;
    ss << hex << setfill('0') << setw(8) << h0
        << setw(8) << h1
        << setw(8) << h2
        << setw(8) << h3
        << setw(8) << h4;

    return ss.str();
}

int main() {
    setlocale(LC_ALL, "");
    
    auto start = std::chrono::high_resolution_clock::now();
    string hash = sha1("Hello, world!");
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    
    auto start_second = std::chrono::high_resolution_clock::now();
    string hash_second = sha1("Lorem Ipsum is simply dummy text of the printing and typesetting industry.");
    auto stop_second = std::chrono::high_resolution_clock::now();
    auto duration_second = std::chrono::duration_cast<std::chrono::microseconds>(stop_second - start_second);

    cout << "#1 SHA-1: " << hash << endl;
    cout << "Время выполнения: " << duration.count() << " мкс\n" << endl;

    cout << "#2 SHA-1: " << hash_second << endl;
    cout << "Время выполнения: " << duration_second.count() << " мкс" << endl;

    return 0;
}
