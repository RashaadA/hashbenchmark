#include <iostream>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/bn.h>

using namespace std;
using namespace boost::multiprecision;

// random constant 2^64 bit prime p 
BIGNUM* prime = BN_new(); 
int ret = BN_generate_prime_ex(prime, 64, 0, NULL, NULL, NULL); 
uint64_t p = BN_get_word(prime);

struct Matrix {
    uint64_t a, b, c, d; // [[a, b], [c, d]]
};

// Less expensive modulo operation
inline uint64_t reduce(uint128_t x)
{
    uint64_t low = (uint64_t)x;
    uint64_t high = (uint64_t)(x >> 64);

    uint64_t res = low - high * 59;
    if (res > low) res -= p;
    return res;
}

//  inline matrix multiplication for each constant (A, B, C)

inline void mulA(Matrix& H)
{
    uint128_t t;

    t = (uint128_t)H.a + 0;
    uint64_t a = reduce(t);

    t = (uint128_t)H.a * 2 + (uint128_t)H.b;
    uint64_t b = reduce(t);

    t = (uint128_t)H.c;
    uint64_t c = reduce(t);

    t = (uint128_t)H.c * 2 + H.d;
    uint64_t d = reduce(t);

    H = { a, b, c, d };
}

inline void mulB(Matrix& H)
{
    uint128_t t;

    t = (uint128_t)H.a + H.b * 2;
    uint64_t a = reduce(t);

    t = (uint128_t)H.a * 1 + H.b;
    uint64_t b = reduce(t);

    t = (uint128_t)H.c + H.d * 2;
    uint64_t c = reduce(t);

    t = (uint128_t)H.c * 1 + H.d;
    uint64_t d = reduce(t);

    H = { a, b, c, d };
}

inline void mulC(Matrix& H)
{
    uint128_t t;

    t = (uint128_t)H.a * 2 + H.b;
    uint64_t a = reduce(t);

    t = (uint128_t)H.a + H.b;
    uint64_t b = reduce(t);

    t = (uint128_t)H.c * 2 + H.d;
    uint64_t c = reduce(t);

    t = (uint128_t)H.c + H.d;
    uint64_t d = reduce(t);

    H = { a, b, c, d };
}

//  byte conversion 

inline void matrixToBytes(const Matrix& m, uint8_t* out)
{
    const uint64_t vals[4] = { m.a, m.b, m.c, m.d };

    for (int i = 0; i < 4; i++) {
        uint64_t v = vals[i];
        out[i * 8 + 0] = (v >> 56) & 0xFF;
        out[i * 8 + 1] = (v >> 48) & 0xFF;
        out[i * 8 + 2] = (v >> 40) & 0xFF;
        out[i * 8 + 3] = (v >> 32) & 0xFF;
        out[i * 8 + 4] = (v >> 24) & 0xFF;
        out[i * 8 + 5] = (v >> 16) & 0xFF;
        out[i * 8 + 6] = (v >> 8) & 0xFF;
        out[i * 8 + 7] = (v >> 0) & 0xFF;
    }
}

// main hash implementation

void cayleyHash(const uint8_t* data, size_t len, uint8_t* out)
{

    Matrix H = { 1, 0, 0, 1 };

    int streak = 0;
    bool last_bit = 0;
    bool cookie_mode = false;

    for (size_t i = 0; i < len; i++)
    {
        uint8_t byte = data[i];

        // manual unroll of bits 
        for (int b = 7; b >= 0; b--)
        {
            bool bit = (byte >> b) & 1;

            // cookie logic
            if (bit == last_bit)
                streak++;
            else
                streak = 1;

            last_bit = bit;

            if (streak >= 3)
                cookie_mode = bit;

            // matrix update
            if (!bit)
                mulA(H);
            else if (cookie_mode)
                mulC(H);
            else
                mulB(H);
        }
    }

    // padding "000"
    for (int i = 0; i < 3; i++)
        mulA(H);

    matrixToBytes(H, out);
}