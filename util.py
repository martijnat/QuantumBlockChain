#!/usr/bin/env python2

# Copyright (C) 2017  Martijn Terpstra

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

def int2bigendian(n, minlen=0):
    r = ""
    while n > 0:
        r = chr(n % 256) + r
        n = n // 256
    while len(r) < minlen:
        r = "\0" + r
    while minlen > 0 and len(r) > minlen:
        r = r[1:]
    return r

def bigendian2int(r):
    n = 0
    while len(r) > 0:
        n = n * 256 + ord(r[0])
        r = r[1:]
    return n

def SHA_padding(L):
    appendix = '\x80'
    appendix += '\x00' * ((55 - L) % 64)
    for bitshift in range(64 - 8, -8, -8):
        appendix += chr((L * 8 >> bitshift) % 256)
    return appendix

def sha_add_length_padding(m):
    L = len(m)
    return m + SHA_padding(L)

def rotr_i32(x, n):
    "Rotate integer n right by b bits"
    return _i32((((x & 0xffffffff) >> (n & 31)) | (x << (32 - (n & 31)))) & 0xffffffff)

def _i32(n):
    return 0xffffffff & n

def shiftr_i32(x, n):
    "shift integer n right by b bits"
    return _i32((x & 0xffffffff) >> n)

def sha256(m):
    "Sha256 on a complete message"

    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    # padd to blocks of 64 bytes
    m = sha_add_length_padding(m)

    for offset in range(0, len(m), 64):
        chunk = m[offset:offset + 64]
        w = [0 for _ in range(64)]
        for i in range(0, 16):
            w[i] = ((ord(chunk[i * 4 + 0]) << 24) +
                    (ord(chunk[i * 4 + 1]) << 16) +
                    (ord(chunk[i * 4 + 2]) << 8) +
                    (ord(chunk[i * 4 + 3]) << 0))

        for i in range(16, 64):
            s0 = rotr_i32(w[i - 15], 7) ^ rotr_i32(
                w[i - 15], 18) ^ shiftr_i32(w[i - 15], 3)
            s1 = rotr_i32(w[i - 2], 17) ^ rotr_i32(w[i - 2], 19) ^ shiftr_i32(w[i - 2], 10)
            w[i] = _i32(w[i - 16] + s0 + w[i - 7] + s1)

        # Initialize working variables to current hash value:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Compression function main loop:
        for i in range(0, 64):
            S1 = rotr_i32(e, 6) ^ rotr_i32(e, 11) ^ rotr_i32(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = h + S1 + ch + k[i] + w[i]
            S0 = rotr_i32(a, 2) ^ rotr_i32(a, 13) ^ rotr_i32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = S0 + maj

            h = g
            g = f
            f = e
            e = _i32(d + temp1)
            d = c
            c = b
            b = a
            a = _i32(temp1 + temp2)

        # Add the compressed chunk to the current hash value:
        h0 = h0 + a
        h1 = h1 + b
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e
        h5 = h5 + f
        h6 = h6 + g
        h7 = h7 + h

    # Produce the final hash value (big-endian):
    return (int2bigendian(h0,4)+
            int2bigendian(h1,4)+
            int2bigendian(h2,4)+
            int2bigendian(h3,4)+
            int2bigendian(h4,4)+
            int2bigendian(h5,4)+
            int2bigendian(h6,4)+
            int2bigendian(h7,4))

def null_padding(s, n):
    "either truncate or padd with null bytes"
    if len(s) <= n:
        return s + ("\0" * (n - len(s)))
    else:
        return s[:n]

def hexstr(s):
    "represpent a string as hex"
    return "".join("%02x" % ord(c) for c in s)
