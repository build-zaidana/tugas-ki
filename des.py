"""DES (Data Encryption Standard) manual, tanpa library kripto.

Alur: key -> 16 subkey; pesan -> blok 8 byte -> 16 ronde Feistel; disambung dengan mode CBC.
Bit disimpan sebagai string, contoh "01101000".

Untuk debug: hapus tanda # di depan baris "# print(...)" yang ada di kode.
"""
import os

# pengacakan awal 64 bit
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# kebalikan IP, dipakai di akhir
FP_TABLE = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# E: 32 bit -> 48 bit
EXPANSION_TABLE = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# permutasi 32 bit setelah S-box
PERMUTATION_TABLE = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]

# key 64 bit -> 56 bit
PC1_TABLE = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# 56 bit -> 48 bit (subkey)
PC2_TABLE = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

S_BOXES = [
    # S-box 1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S-box 2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S-box 3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S-box 4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S-box 5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S-box 6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S-box 7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S-box 8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]

BLOCK_SIZE = 8  # byte


# Fungsi bantu 

def bytes_to_bits(data):
    """b'A' -> '01000001'"""
    bits = ""
    for byte in data:
        bits += format(byte, "08b")
    return bits


def bits_to_bytes(bits):
    """'01000001' -> b'A'"""
    result = []
    for i in range(0, len(bits), 8):
        result.append(int(bits[i:i + 8], 2))
    return bytes(result)


def permute(bits, table):
    """Susun ulang bit sesuai tabel (nomor mulai dari 1)."""
    result = ""
    for position in table:
        result += bits[position - 1]
    return result


def xor_bits(bits_a, bits_b):
    result = ""
    for a, b in zip(bits_a, bits_b):
        result += "0" if a == b else "1"
    return result


def rotate_left(bits, amount):
    """Putar ke kiri: bit yang keluar di kiri masuk lagi di kanan."""
    return bits[amount:] + bits[:amount]


# Langkah 1: 16 subkey 

def generate_subkeys(key):
    """Key 8 byte -> 16 subkey @ 48 bit."""
    if len(key) != 8:
        raise ValueError("Key harus tepat 8 karakter")

    key_56_bits = permute(bytes_to_bits(key), PC1_TABLE)   # 64 -> 56 bit
    left_half, right_half = key_56_bits[:28], key_56_bits[28:]
    # print("key bit      :", bytes_to_bits(key))
    # print("setelah PC1  :", key_56_bits, f"({len(key_56_bits)} bit)")

    subkeys = []
    for round_index in range(16):
        left_half = rotate_left(left_half, KEY_SHIFTS[round_index])
        right_half = rotate_left(right_half, KEY_SHIFTS[round_index])
        subkey = permute(left_half + right_half, PC2_TABLE)   # 56 -> 48 bit
        subkeys.append(subkey)
        # print(f"subkey {round_index + 1:2d}    :", subkey)
    return subkeys


# fungsi ronde 

def sbox_substitute(six_bits, sbox_index):
    """6 bit -> 4 bit lewat S-box."""
    row = int(six_bits[0] + six_bits[5], 2)   # bit pertama + terakhir
    column = int(six_bits[1:5], 2)            # 4 bit tengah
    return format(S_BOXES[sbox_index][row][column], "04b")


def round_function(right_half, subkey):
    """32 bit masuk, 32 bit keluar."""
    expanded = permute(right_half, EXPANSION_TABLE)   # 32 -> 48 bit
    xor_result = xor_bits(expanded, subkey)

    sbox_output = ""
    for i in range(8):                                # 8 kelompok  6 bit -> 4 bit
        sbox_output += sbox_substitute(xor_result[i * 6:(i + 1) * 6], i)

    result = permute(sbox_output, PERMUTATION_TABLE)
    # print("E(R):", expanded)
    # print("xor key:", xor_result)
    # print("sbox:", sbox_output)
    # print("hasil f:", result)
    return result


# satu blok (8 byte) 

def process_block(block, subkeys):
    """16 ronde Feistel. Dekripsi = fungsi yang sama dengan subkey dibalik."""
    bits = permute(bytes_to_bits(block), IP_TABLE)
    left_half, right_half = bits[:32], bits[32:]
    # print("blok masuk   :", bytes_to_bits(block))
    # print("setelah IP   :", bits)

    for round_number, subkey in enumerate(subkeys, 1):
        # print(f"ronde {round_number:2d}")
        new_left = right_half
        new_right = xor_bits(left_half, round_function(right_half, subkey))
        left_half, right_half = new_left, new_right
        # print("L:", left_half)
        # print("R:", right_half)

    result = permute(right_half + left_half, FP_TABLE)   # kiri-kanan ditukar sebelum FP
    # print("blok keluar  :", result)
    return bits_to_bytes(result)


def encrypt_block(block, key):
    return process_block(block, generate_subkeys(key))


def decrypt_block(block, key):
    return process_block(block, generate_subkeys(key)[::-1])


# Padding 

def add_padding(data):
    """Tambah n byte bernilai n supaya panjang jadi kelipatan 8."""
    pad_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_length]) * pad_length


def remove_padding(data):
    pad_length = data[-1]
    if pad_length < 1 or pad_length > BLOCK_SIZE or data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Padding tidak valid (key salah atau data rusak)")
    return data[:-pad_length]


def xor_bytes(bytes_a, bytes_b):
    result = []
    for a, b in zip(bytes_a, bytes_b):
        result.append(a ^ b)
    return bytes(result)


# CBC

def encrypt_cbc(plaintext, key):
    """Hasil = IV (8 byte) + ciphertext."""
    iv = os.urandom(BLOCK_SIZE)
    padded = add_padding(plaintext)
    # print("CBC enkripsi: IV =", iv.hex(), "| setelah padding =", padded.hex())

    previous_block = iv
    ciphertext = b""
    for i in range(0, len(padded), BLOCK_SIZE):
        block = xor_bytes(padded[i:i + BLOCK_SIZE], previous_block)
        previous_block = encrypt_block(block, key)
        ciphertext += previous_block
        # print(f"CBC blok {i // BLOCK_SIZE + 1} -> cipher =", previous_block.hex())
    return iv + ciphertext


def decrypt_cbc(packet, key):
    if len(packet) < 2 * BLOCK_SIZE or len(packet) % BLOCK_SIZE != 0:
        raise ValueError("Panjang ciphertext tidak valid")

    iv, ciphertext = packet[:BLOCK_SIZE], packet[BLOCK_SIZE:]
    # print("CBC dekripsi: IV =", iv.hex())

    previous_block = iv
    padded = b""
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        padded += xor_bytes(decrypt_block(block, key), previous_block)
        previous_block = block
    # print("CBC dekripsi: sebelum buang padding =", padded.hex())
    return remove_padding(padded)
