#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <bitset>
#include <string>

// Right rotate operation
uint32_t rightRotate(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Padding the input message to a multiple of 512 bits
std::vector<uint8_t> padMessage(const std::string& message) {
    size_t originalLength = message.size() * 8;
    std::vector<uint8_t> paddedMessage(message.begin(), message.end());

    // Add the '1' bit
    paddedMessage.push_back(0x80);

    // Padding with zeros
    while ((paddedMessage.size() * 8) % 512 != 448) {
        paddedMessage.push_back(0);
    }

    // Append the original length
    for (int i = 7; i >= 0; --i) {
        paddedMessage.push_back((originalLength >> (i * 8)) & 0xff);
    }

    return paddedMessage;
}

// Process a 512-bit chunk
void processChunk(const uint8_t* chunk, uint32_t* hash) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16) |
               (chunk[i * 4 + 2] << 8) | (chunk[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    uint32_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + W[i];
        uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

// SHA-256 hash function
std::string sha256(const std::string& message) {
    uint32_t hash[8];
    std::copy(std::begin(H), std::end(H), hash);

    std::vector<uint8_t> paddedMessage = padMessage(message);
    for (size_t i = 0; i < paddedMessage.size(); i += 64) {
        processChunk(&paddedMessage[i], hash);
    }

    std::ostringstream result;
    for (int i = 0; i < 8; ++i) {
        result << std::hex << std::setw(8) << std::setfill('0') << hash[i];
    }

    return result.str();
}

int main() {
    std::string input;
    std::cout << "Enter the text: ";
    std::getline(std::cin, input);

    std::string hash = sha256(input);
    std::cout << "SHA-256: " << hash << std::endl;

    return 0;
}
