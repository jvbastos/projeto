#include <iostream>
#include <fstream>
#include <vector>
#include <array>
#include <string>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <cstring>

using Byte = uint8_t;
using Block = std::array<Byte, 16>;

class AES128 {
private:
    std::array<Byte, 176> roundKeys{};

    static constexpr Byte sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    static constexpr Byte invSbox[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    static constexpr Byte rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

    static Byte gmul(Byte a, Byte b) {
        Byte p = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) p ^= a;
            bool hi = a & 0x80;
            a <<= 1;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    static void subBytes(Block& state) {
        for (Byte& b : state) b = sbox[b];
    }

    static void invSubBytes(Block& state) {
        for (Byte& b : state) b = invSbox[b];
    }

    static void shiftRows(Block& state) {
        Block temp = state;
        state[0] = temp[0];   state[4] = temp[4];   state[8] = temp[8];   state[12] = temp[12];
        state[1] = temp[5];   state[5] = temp[9];   state[9] = temp[13];  state[13] = temp[1];
        state[2] = temp[10];  state[6] = temp[14];  state[10] = temp[2];  state[14] = temp[6];
        state[3] = temp[15];  state[7] = temp[3];   state[11] = temp[7];  state[15] = temp[11];
    }

    static void invShiftRows(Block& state) {
        Block temp = state;
        state[0] = temp[0];   state[4] = temp[4];   state[8] = temp[8];   state[12] = temp[12];
        state[1] = temp[13];  state[5] = temp[1];   state[9] = temp[5];   state[13] = temp[9];
        state[2] = temp[10];  state[6] = temp[14];  state[10] = temp[2];  state[14] = temp[6];
        state[3] = temp[7];   state[7] = temp[11];  state[11] = temp[15]; state[15] = temp[3];
    }

    static void mixColumns(Block& state) {
        for (int c = 0; c < 4; ++c) {
            int i = c * 4;
            Byte a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
            state[i]   = gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3;
            state[i+1] = a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3;
            state[i+2] = a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3);
            state[i+3] = gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2);
        }
    }

    static void invMixColumns(Block& state) {
        for (int c = 0; c < 4; ++c) {
            int i = c * 4;
            Byte a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
            state[i]   = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
            state[i+1] = gmul(a0,9) ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
            state[i+2] = gmul(a0,13) ^ gmul(a1,9) ^ gmul(a2,14) ^ gmul(a3,11);
            state[i+3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9) ^ gmul(a3,14);
        }
    }

    void addRoundKey(Block& state, int round) const {
        for (int i = 0; i < 16; ++i) {
            state[i] ^= roundKeys[round * 16 + i];
        }
    }

    void keyExpansion(const Block& key) {
        for (int i = 0; i < 16; ++i) roundKeys[i] = key[i];

        int bytesGenerated = 16;
        int rconIteration = 1;
        Byte temp[4];

        while (bytesGenerated < 176) {
            for (int i = 0; i < 4; ++i) temp[i] = roundKeys[bytesGenerated - 4 + i];

            if (bytesGenerated % 16 == 0) {
                Byte t = temp[0];
                temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                for (int i = 0; i < 4; ++i) temp[i] = sbox[temp[i]];
                temp[0] ^= rcon[rconIteration++];
            }

            for (int i = 0; i < 4; ++i) {
                roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
                ++bytesGenerated;
            }
        }
    }

public:
    explicit AES128(const Block& key) {
        keyExpansion(key);
    }

    Block encryptBlock(const Block& input) const {
        Block state = input;
        addRoundKey(state, 0);

        for (int round = 1; round <= 9; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, 10);
        return state;
    }

    Block decryptBlock(const Block& input) const {
        Block state = input;
        addRoundKey(state, 10);

        for (int round = 9; round >= 1; --round) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
        return state;
    }
};

std::vector<Byte> readBinaryFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Erro ao abrir arquivo de entrada: " + filePath);
    }
    return std::vector<Byte>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void writeBinaryFile(const std::string& filePath, const std::vector<Byte>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Erro ao criar arquivo de saída: " + filePath);
    }
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

Block deriveKeyFromString(const std::string& keyString) {
    Block key{};
    for (size_t i = 0; i < 16; ++i) {
        if (i < keyString.size()) key[i] = static_cast<Byte>(keyString[i]);
        else key[i] = 0x00;
    }
    return key;
}

Block deriveIVFromKey(const Block& key) {
    Block iv{};
    for (size_t i = 0; i < 16; ++i) {
        iv[i] = static_cast<Byte>((key[i] ^ static_cast<Byte>(0xA5 + i * 7)) & 0xFF);
    }
    return iv;
}

std::vector<Byte> applyPKCS7Padding(const std::vector<Byte>& data, size_t blockSize = 16) {
    std::vector<Byte> padded = data;
    Byte padValue = static_cast<Byte>(blockSize - (data.size() % blockSize));
    if (padValue == 0) padValue = static_cast<Byte>(blockSize);
    padded.insert(padded.end(), padValue, padValue);
    return padded;
}

std::vector<Byte> removePKCS7Padding(const std::vector<Byte>& data, size_t blockSize = 16) {
    if (data.empty() || data.size() % blockSize != 0) {
        throw std::runtime_error("Dados inválidos para remoção de padding.");
    }

    Byte padValue = data.back();
    if (padValue == 0 || padValue > blockSize || padValue > data.size()) {
        throw std::runtime_error("Padding PKCS#7 inválido.");
    }

    for (size_t i = data.size() - padValue; i < data.size(); ++i) {
        if (data[i] != padValue) {
            throw std::runtime_error("Padding PKCS#7 corrompido.");
        }
    }

    return std::vector<Byte>(data.begin(), data.end() - padValue);
}

Block vectorToBlock(const std::vector<Byte>& data, size_t offset) {
    Block block{};
    for (size_t i = 0; i < 16; ++i) block[i] = data[offset + i];
    return block;
}

void blockToVector(const Block& block, std::vector<Byte>& out) {
    out.insert(out.end(), block.begin(), block.end());
}

Block xorBlocks(const Block& a, const Block& b) {
    Block result{};
    for (size_t i = 0; i < 16; ++i) result[i] = a[i] ^ b[i];
    return result;
}

std::vector<Byte> encryptCBC(const std::vector<Byte>& plainData, const std::string& keyString) {
    Block key = deriveKeyFromString(keyString);
    Block iv = deriveIVFromKey(key);
    AES128 aes(key);

    std::vector<Byte> padded = applyPKCS7Padding(plainData);
    std::vector<Byte> encrypted;
    encrypted.reserve(padded.size() + 16);

    blockToVector(iv, encrypted);

    Block previous = iv;
    for (size_t i = 0; i < padded.size(); i += 16) {
        Block current = vectorToBlock(padded, i);
        Block xored = xorBlocks(current, previous);
        Block cipher = aes.encryptBlock(xored);
        blockToVector(cipher, encrypted);
        previous = cipher;
    }

    return encrypted;
}

std::vector<Byte> decryptCBC(const std::vector<Byte>& cipherData, const std::string& keyString) {
    if (cipherData.size() < 32 || cipherData.size() % 16 != 0) {
        throw std::runtime_error("Arquivo cifrado inválido.");
    }

    Block key = deriveKeyFromString(keyString);
    AES128 aes(key);

    Block iv = vectorToBlock(cipherData, 0);
    std::vector<Byte> decrypted;
    decrypted.reserve(cipherData.size() - 16);

    Block previous = iv;
    for (size_t i = 16; i < cipherData.size(); i += 16) {
        Block current = vectorToBlock(cipherData, i);
        Block plain = xorBlocks(aes.decryptBlock(current), previous);
        blockToVector(plain, decrypted);
        previous = current;
    }

    return removePKCS7Padding(decrypted);
}

void printUsage(const std::string& programName) {
    std::cout << "Uso:\n";
    std::cout << "  " << programName << " encrypt <arquivo_entrada> <arquivo_saida> <chave>\n";
    std::cout << "  " << programName << " decrypt <arquivo_entrada> <arquivo_saida> <chave>\n\n";
    std::cout << "Exemplos:\n";
    std::cout << "  " << programName << " encrypt imagem.jpg imagem.enc minhaChave123\n";
    std::cout << "  " << programName << " decrypt imagem.enc imagem_restaurada.jpg minhaChave123\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            printUsage(argv[0]);
            return 1;
        }

        std::string operation = argv[1];
        std::string inputFile = argv[2];
        std::string outputFile = argv[3];
        std::string key = argv[4];

        if (key.empty()) {
            throw std::runtime_error("A chave não pode ser vazia.");
        }

        std::vector<Byte> inputData = readBinaryFile(inputFile);
        std::vector<Byte> outputData;

        if (operation == "encrypt") {
            outputData = encryptCBC(inputData, key);
            writeBinaryFile(outputFile, outputData);
            std::cout << "Arquivo cifrado com sucesso.\n";
            std::cout << "Entrada: " << inputFile << "\n";
            std::cout << "Saída:   " << outputFile << "\n";
            std::cout << "Tamanho original: " << inputData.size() << " bytes\n";
            std::cout << "Tamanho cifrado:  " << outputData.size() << " bytes\n";
        } else if (operation == "decrypt") {
            outputData = decryptCBC(inputData, key);
            writeBinaryFile(outputFile, outputData);
            std::cout << "Arquivo decifrado com sucesso.\n";
            std::cout << "Entrada: " << inputFile << "\n";
            std::cout << "Saída:   " << outputFile << "\n";
            std::cout << "Tamanho cifrado:   " << inputData.size() << " bytes\n";
            std::cout << "Tamanho restaurado:" << outputData.size() << " bytes\n";
        } else {
            printUsage(argv[0]);
            return 1;
        }

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Erro: " << e.what() << "\n";
        return 1;
    }
}
