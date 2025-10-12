#include <bits/stdc++.h>
using namespace std;

int initialPermutation[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

int permutation[32] = {
    16, 7, 20, 21, 29,12, 28,17,
    1,15, 23,26, 5,18, 31,10,
    2, 8, 24,14, 32,27,  3, 9,
    19,13, 30, 6, 22,11,  4,25
};

int finalPermutation[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

int expansion[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32, 1
};

int sBox[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

int pc1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

int pc2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

int shiftTable[16] = {
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
};

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return 0;
}

string hex_to_bin(const string &s) {
    static const string nibble[16] = {
        "0000","0001","0010","0011","0100","0101","0110","0111",
        "1000","1001","1010","1011","1100","1101","1110","1111"
    };
    string out = "";
    for (char c: s) {
        out += nibble[hexCharToInt(c)];
    }
    return out;
}

string bin_to_hex(const string &s) {
    static const char hexchr[] = "0123456789ABCDEF";
    string out = "";
    for (size_t i = 0; i < s.size(); i += 4) {
        int v = (s[i]-'0')*8 + (s[i+1]-'0')*4 + (s[i+2]-'0')*2 + (s[i+3]-'0');
        out.push_back(hexchr[v]);
    }
    return out;
}

string bitset64_to_binstr(const bitset<64> &b) {
    string s;
    s.reserve(64);
    for (int i = 63; i >= 0; --i) s.push_back(b[i] ? '1' : '0');
    return s;
}

bitset<64> binstr_to_bitset64(const string &s) {
    bitset<64> b;
    for (int i = 0; i < 64 && i < (int)s.size(); ++i) {
        b[63 - i] = (s[i] == '1');
    }
    return b;
}

bitset<64> hexstr_to_bitset64(const string &hex16) {
    return binstr_to_bitset64(hex_to_bin(hex16));
}

string bitset64_to_hexstr(const bitset<64> &b) {
    return bin_to_hex( bitset64_to_binstr(b) );
}

template<int INBITS>
bitset<INBITS> permute_bits(const bitset<64> &input, const int *table, int n) {
    bitset<64> output;
    for (int i = 0; i < n; i++) {
        output[n - 1 - i] = input[64 - table[i]];
    }
    bitset<INBITS> ret;
    for (int i = 0; i < n && i < INBITS; ++i) {
        ret[INBITS - 1 - i] = output[n - 1 - i];
    }
    return ret;
}

bitset<64> permute64(const bitset<64> &input, int* table, int n) {
    bitset<64> out;
    for (int i = 0; i < n; i++) {
        out[n - 1 - i] = input[64 - table[i]];
    }
    return out;
}

vector<bitset<48>> generateSubkeys(bitset<64> key) {
    vector<bitset<48>> subkeys;
    bitset<64> permutedKey64;
    for (int i = 0; i < 56; i++) {
        permutedKey64[55 - i] = key[64 - pc1[i]];
    }

    bitset<28> C, D;
    for (int i = 0; i < 28; i++) {
        C[27 - i] = permutedKey64[55 - i];
        D[27 - i] = permutedKey64[27 - i];
    }

    for (int round = 0; round < 16; round++) {
        int sh = shiftTable[round];
        C = (C << sh) | (C >> (28 - sh));
        D = (D << sh) | (D >> (28 - sh));
        bitset<56> CD;
        for (int i = 0; i < 28; i++) {
            CD[i + 28] = C[i];
            CD[i] = D[i];
        }
        bitset<48> subkey;
        for (int i = 0; i < 48; i++) {
            subkey[47 - i] = CD[56 - pc2[i]];
        }
        subkeys.push_back(subkey);
    }

    return subkeys;
}

bitset<32> feistel(bitset<32> R, bitset<48> subkey) {
    bitset<48> expandedR;
    for (int i = 0; i < 48; i++) {
        expandedR[47 - i] = R[32 - expansion[i]];
    }
    expandedR ^= subkey;
    bitset<32> output32;
    int pos = 31;
    for (int i = 0; i < 8; i++) {
        int bitIndexBase = 47 - (i * 6);
        int row = (expandedR[bitIndexBase] << 1) | expandedR[bitIndexBase - 5];
        int col = 0;
        for (int j = 1; j <= 4; j++) {
            col |= expandedR[bitIndexBase - j] << (4 - j);
        }
        int val = sBox[i][row][col];
        for (int k = 0; k < 4; k++) {
            output32[pos--] = ( (val >> k) & 1 );
        }
    }
    bitset<32> permutedOutput;
    for (int i = 0; i < 32; i++) {
        permutedOutput[31 - i] = output32[32 - permutation[i]];
    }

    return permutedOutput;
}

string encrypt_block_hex(const string &plain_hex16, const vector<bitset<48>> &subkeys) {
    bitset<64> pt = hexstr_to_bitset64(plain_hex16);
    bitset<64> ip = permute64(pt, initialPermutation, 64);
    bitset<32> L, R;
    for (int i = 0; i < 32; i++) {
        L[31 - i] = ip[63 - i];
        R[31 - i] = ip[31 - i];
    }

    for (int i = 0; i < 16; i++) {
        bitset<32> temp = R;
        bitset<32> f = feistel(R, subkeys[i]);
        R = L ^ f;
        L = temp;
    }

    bitset<64> preOut;
    for (int i = 0; i < 32; i++) {
        preOut[63 - i] = R[31 - i];
        preOut[31 - i] = L[31 - i];
    }
    bitset<64> ct = permute64(preOut, finalPermutation, 64);
    return bitset64_to_hexstr(ct);
}

string decrypt_block_hex(const string &cipher_hex16, const vector<bitset<48>> &subkeys) {
    vector<bitset<48>> rev = subkeys;
    reverse(rev.begin(), rev.end());
    return encrypt_block_hex(cipher_hex16, rev);
}

vector<string> input_encrypt_blocks_from_text() {
    string input_text;
    cout << "Input text: ";
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getline(cin, input_text);

    vector<string> plain_blocks;
    plain_blocks.push_back("");
    int k = 0;
    for (int i = 0; i < (int)input_text.length(); i++) {
        unsigned char ch = input_text[i];
        string character = "";
        for (int j = 7; j >= 0; j--) {
            character.push_back( (ch & (1 << j)) ? '1' : '0' );
        }
        string left = character.substr(0, 4);
        string right = character.substr(4, 4);
        plain_blocks[k] += bin_to_hex(left) + bin_to_hex(right);

        if ((int)plain_blocks[k].length() == 16) {
            plain_blocks.push_back("");
            k++;
        }
    }

    if (plain_blocks.back().length() != 16) {
        for (size_t i = plain_blocks.back().length(); i < 16; ++i) plain_blocks.back().push_back('0');
    }

    if (!plain_blocks.empty() && plain_blocks.back().empty()) plain_blocks.pop_back();
    return plain_blocks;
}

string output_decrypt_to_text(const vector<string> &plain_hex_blocks) {
    string ret = "";
    for (const string &block : plain_hex_blocks) {
        for (int j = 0; j < 16; j += 2) {
            string two_hex = block.substr(j, 2);
            int value = stoi(two_hex, nullptr, 16);
            if (value != 0) ret.push_back(static_cast<char>(value));
        }
    }
    return ret;
}

string generate_key_hex() {
    static const char hexchars[] = "0123456789ABCDEF";
    std::mt19937 rng((unsigned)chrono::high_resolution_clock::now().time_since_epoch().count());
    uniform_int_distribution<int> dist(0, 15);
    string key = "";
    for (int i = 0; i < 16; ++i) key.push_back(hexchars[dist(rng)]);
    return key;
}

int main() {
    while (true) {
        cout << "Choose Option(1/2/3):" << '\n';
        cout << "1. Encrypt Text" << '\n';
        cout << "2. Decrypt Text" << '\n';
        cout << "3. Exit" << '\n';
        cout << "input your choice: ";
        int opsi;
        if (!(cin >> opsi)) break;

        if (opsi == 1) {
            vector<string> plain_blocks = input_encrypt_blocks_from_text();
            int message_size = plain_blocks.size();
            string key_hex = generate_key_hex();
            bitset<64> key_bs = hexstr_to_bitset64(key_hex);
            vector<bitset<48>> subkeys = generateSubkeys(key_bs);
            vector<string> cipher_blocks;
            for (int i = 0; i < message_size; i++) {
                string ct = encrypt_block_hex(plain_blocks[i], subkeys);
                cipher_blocks.push_back(ct);
                cout << "Plain text encrypted [" << i + 1 << "/" << message_size << "]" << '\n';
            }
            cout << "Key = " << key_hex << '\n';
            cout << "Cipher text = ";
            for (const string &s : cipher_blocks) cout << s;
            cout << '\n' << '\n';
        } else if (opsi == 2) {
            string key_hex, cipher_text;
            cout << "Input key: ";
            cin >> key_hex;
            cout << "Input cipher text: ";
            cin >> cipher_text;
            bitset<64> key_bs = hexstr_to_bitset64(key_hex);
            vector<bitset<48>> subkeys = generateSubkeys(key_bs);

            int message_size = cipher_text.length() / 16;
            vector<string> plain_hex_blocks;
            for (int i = 0; i < (int)cipher_text.length(); i += 16) {
                string ct_block = cipher_text.substr(i, 16);
                string pt_hex = decrypt_block_hex(ct_block, subkeys);
                plain_hex_blocks.push_back(pt_hex);
                cout << "Cipher text decrypted [" << i/16 + 1 << "/" << message_size << "]" << '\n';
            }

            string plain_text = output_decrypt_to_text(plain_hex_blocks);
            cout << "Plain text: " << plain_text << '\n';
        } else if (opsi == 3) {
            cout << "Goodbye!" << '\n';
            break;
        } else {
            cout << "Pilih opsi yang tersedia (1, 2, atau 3)" << '\n';
        }
    }
    return 0;
}