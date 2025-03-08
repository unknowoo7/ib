#include <iostream>
#include <vector>
#include <array>
#include <bitset>
#include <cstring>
#include <chrono>

const int ROUNDS = 24;
const int STATE_SIZE = 1600 / 64;
const int SHA3_256_RATE = 1088 / 8;
const int OUTPUT_SIZE = 256 / 8;

using State = std::array<uint64_t, STATE_SIZE>;

const uint64_t ROUND_CONSTANTS[ROUNDS] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

void keccakPermutation(State& state) {
	for (int round = 0; round < ROUNDS; ++round) {
		uint64_t C[5], D[5];
		for (int x = 0; x < 5; ++x) {
			C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
		}
		for (int x = 0; x < 5; ++x) {
			D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63));
		}
		for (int i = 0; i < 25; ++i) {
			state[i] ^= D[i % 5];
		}
		state[0] ^= ROUND_CONSTANTS[round];
	}
}

std::vector<uint8_t> sha3_256(const std::vector<uint8_t>& input) {
	State state = {};
	std::vector<uint8_t> paddedInput = input;
	paddedInput.push_back(0x06);
	while (paddedInput.size() % SHA3_256_RATE != SHA3_256_RATE - 1) {
		paddedInput.push_back(0x00);
	}
	paddedInput.push_back(0x80);

	for (size_t i = 0; i < paddedInput.size(); i += SHA3_256_RATE) {
		for (size_t j = 0; j < SHA3_256_RATE / 8; ++j) {
			uint64_t chunk = 0;
			memcpy(&chunk, &paddedInput[i + j * 8], 8);
			state[j] ^= chunk;
		}
		keccakPermutation(state);
	}

	std::vector<uint8_t> output(OUTPUT_SIZE);
	memcpy(output.data(), state.data(), OUTPUT_SIZE);
	return output;
}

int main() {
	setlocale(0, "");
	auto start = std::chrono::high_resolution_clock::now();
	std::string message = "Hello, world!";
	std::vector<uint8_t> input(message.begin(), message.end());
	std::vector<uint8_t> hash = sha3_256(input);
	std::cout << "SHA3-256: ";
	for (uint8_t byte : hash) {
		printf("%02x", byte);
	}
	std::cout << std::endl;
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> elapsed = end - start; // Разница во времени
	std::cout << "Время выполнения: " << elapsed.count() << " секунд" << std::endl;


	auto start_2 = std::chrono::high_resolution_clock::now();
	std::string message_2 = "There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc.";
	std::vector<uint8_t> input_2(message_2.begin(), message_2.end());
	std::vector<uint8_t> hash_2 = sha3_256(input_2);
	std::cout << "SHA3-256: ";
	for (uint8_t byte : hash_2) {
		printf("%02x", byte);
	}
	std::cout << std::endl;
	auto end_2 = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> elapsed_2 = end_2 - start_2; // Разница во времени
	std::cout << "Время выполнения: " << elapsed_2.count() << " секунд" << std::endl;

	return 0;
}