#include <cstdint>
#include "cayleyhash.h"
#include <cstddef>

#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/bn.h>

#include <array>
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <limits>

using u128 = boost::multiprecision::uint128_t;

// ============================================================
// Modulus management
// ============================================================

// The modulus must be initialized before hashing begins.
static uint64_t P = 0;

// Generate a random 64-bit prime.
uint64_t generateRandomPrime64()
{
    BIGNUM* prime = BN_new();

    if (prime == nullptr)
        throw std::runtime_error(
            "Failed to allocate BIGNUM."
        );

    const int generated = BN_generate_prime_ex(
        prime,
        64,
        0,
        nullptr,
        nullptr,
        nullptr
    );

    if (generated != 1)
    {
        BN_free(prime);

        throw std::runtime_error(
            "Failed to generate a random prime."
        );
    }

    unsigned char bytes[8];

    if (BN_bn2binpad(
        prime,
        bytes,
        sizeof(bytes)
    ) != sizeof(bytes))
    {
        BN_free(prime);

        throw std::runtime_error(
            "Failed to convert the generated prime."
        );
    }

    BN_free(prime);

    uint64_t value = 0;

    for (unsigned char byte : bytes)
        value = (value << 8) | byte;

    return value;
}

// Check whether a decimal string represents a 64-bit prime.
bool isValidPrime64(const std::string& number)
{
    if (number.empty())
        return false;

    for (char ch : number)
    {
        if (ch < '0' || ch > '9')
            return false;
    }

    BIGNUM* candidate = nullptr;

    if (BN_dec2bn(&candidate, number.c_str()) == 0)
        return false;

    if (BN_is_negative(candidate) ||
        BN_num_bits(candidate) > 64)
    {
        BN_free(candidate);
        return false;
    }

    BN_CTX* ctx = BN_CTX_new();

    if (ctx == nullptr)
    {
        BN_free(candidate);

        throw std::runtime_error(
            "Failed to allocate OpenSSL context."
        );
    }

    const int result = BN_check_prime(
        candidate,
        ctx,
        nullptr
    );

    BN_CTX_free(ctx);
    BN_free(candidate);

    if (result < 0)
    {
        throw std::runtime_error(
            "OpenSSL primality check failed."
        );
    }

    return result == 1;
}

// Convert a validated decimal prime to uint64_t.
uint64_t parsePrime64(const std::string& number)
{
    if (!isValidPrime64(number))
    {
        throw std::invalid_argument(
            "The modulus must be a valid 64-bit prime."
        );
    }

    return std::stoull(number);
}

// Set the modulus used by the hash.
void setCayleyHashModulus(uint64_t modulus)
{
    if (!isValidPrime64(std::to_string(modulus)))
    {
        throw std::invalid_argument(
            "The modulus must be a valid 64-bit prime."
        );
    }

    P = modulus;
}

// Return the active modulus.
uint64_t getCayleyHashModulus()
{
    if (P == 0)
    {
        throw std::runtime_error(
            "Initialize the modulus before hashing."
        );
    }

    return P;
}

// Save the active modulus to a file.
void saveCayleyHashModulus(
    const std::string& filename
)
{
    if (P == 0)
    {
        throw std::runtime_error(
            "The modulus has not been initialized."
        );
    }

    std::ofstream file(filename);

    if (!file)
    {
        throw std::runtime_error(
            "Could not open the modulus file for writing."
        );
    }

    file << P << '\n';

    if (!file)
    {
        throw std::runtime_error(
            "Failed to save the modulus."
        );
    }
}

// Load a previously saved modulus.
uint64_t loadCayleyHashModulus(
    const std::string& filename
)
{
    std::ifstream file(filename);

    if (!file)
    {
        throw std::runtime_error(
            "Could not open the modulus file."
        );
    }

    std::string number;
    std::string extra;

    if (!(file >> number))
    {
        throw std::runtime_error(
            "The modulus file is empty."
        );
    }

    if (file >> extra)
    {
        throw std::runtime_error(
            "The modulus file contains unexpected data."
        );
    }

    return parsePrime64(number);
}

// Initialize the modulus using a menu.
void initializeCayleyHashModulus()
{
    int choice;

    std::cout
        << "\nCayley Hash Modulus Selection\n"
        << "1. Generate a random 64-bit prime\n"
        << "2. Enter a prime manually\n"
        << "3. Load a saved prime\n"
        << "Select an option: ";

    if (!(std::cin >> choice))
    {
        std::cin.clear();

        std::cin.ignore(
            std::numeric_limits<std::streamsize>::max(),
            '\n'
        );

        throw std::runtime_error(
            "Invalid menu selection."
        );
    }

    switch (choice)
    {
    case 1:
    {
        P = generateRandomPrime64();

        std::cout
            << "Generated prime: "
            << P << '\n';

        break;
    }

    case 2:
    {
        std::string input;

        std::cout
            << "Enter a 64-bit prime: ";

        std::cin >> input;

        P = parsePrime64(input);

        std::cout
            << "Using prime: "
            << P << '\n';

        break;
    }

    case 3:
    {
        std::string filename;

        std::cout
            << "Enter the modulus filename: ";

        std::cin >> filename;

        P = loadCayleyHashModulus(filename);

        std::cout
            << "Loaded prime: "
            << P << '\n';

        break;
    }

    default:
    {
        throw std::invalid_argument(
            "Invalid menu option."
        );
    }
    }

    char saveChoice;

    std::cout
        << "Save this prime for future runs? (y/n): ";

    std::cin >> saveChoice;

    if (saveChoice == 'y' || saveChoice == 'Y')
    {
        std::string filename;

        std::cout
            << "Enter the filename: ";

        std::cin >> filename;

        saveCayleyHashModulus(filename);

        std::cout
            << "Prime saved to "
            << filename << '\n';
    }
}

// ============================================================
// Matrix representation and modular arithmetic
// ============================================================

struct Matrix
{
    uint64_t a, b, c, d;
};

// Reduce a 128-bit integer modulo P.
inline uint64_t reduce(u128 x)
{
    if (P == 0)
    {
        throw std::runtime_error(
            "Initialize the modulus before hashing."
        );
    }

    return static_cast<uint64_t>(x % P);
}

// Add two reduced values modulo P.
inline uint64_t addMod(uint64_t x, uint64_t y)
{
    return reduce(static_cast<u128>(x) + y);
}

// Matrix transformation A.
inline void mulA(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    H.b = reduce(
        static_cast<u128>(a) * 2 + b
    );

    H.d = reduce(
        static_cast<u128>(c) * 2 + d
    );
}

// Matrix transformation B.
inline void mulB(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    H.a = reduce(
        static_cast<u128>(a) +
        static_cast<u128>(b) * 2
    );

    H.c = reduce(
        static_cast<u128>(c) +
        static_cast<u128>(d) * 2
    );
}

// Matrix transformation C.
inline void mulC(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    H.a = reduce(
        static_cast<u128>(a) * 2 + b
    );

    H.b = reduce(
        static_cast<u128>(a) + b
    );

    H.c = reduce(
        static_cast<u128>(c) * 2 + d
    );

    H.d = reduce(
        static_cast<u128>(c) + d
    );
}

// ============================================================
// Cookie state
// ============================================================

inline uint8_t makeState(
    uint8_t lastBit,
    uint8_t streak,
    uint8_t cookieMode
)
{
    return static_cast<uint8_t>(
        (lastBit & 1) |
        ((streak & 3) << 1) |
        ((cookieMode & 1) << 3)
        );
}

inline void decodeState(
    uint8_t state,
    uint8_t& lastBit,
    uint8_t& streak,
    uint8_t& cookieMode
)
{
    lastBit = state & 1;
    streak = (state >> 1) & 3;
    cookieMode = (state >> 3) & 1;
}

inline uint8_t processBitState(
    uint8_t state,
    uint8_t bit
)
{
    uint8_t lastBit;
    uint8_t streak;
    uint8_t cookieMode;

    decodeState(
        state,
        lastBit,
        streak,
        cookieMode
    );

    if (bit == lastBit)
    {
        if (streak < 3)
            ++streak;
    }
    else
    {
        streak = 1;
    }

    lastBit = bit;

    if (streak >= 3)
        cookieMode = bit;

    return makeState(
        lastBit,
        streak,
        cookieMode
    );
}

inline void processBit(
    Matrix& H,
    uint8_t& state,
    uint8_t bit
)
{
    uint8_t lastBit;
    uint8_t streak;
    uint8_t cookieMode;

    decodeState(
        state,
        lastBit,
        streak,
        cookieMode
    );

    if (!bit)
    {
        mulA(H);
    }
    else if (cookieMode)
    {
        mulC(H);
    }
    else
    {
        mulB(H);
    }

    state = processBitState(state, bit);
}

// ============================================================
// Byte transition table
// ============================================================

struct Transition
{
    Matrix matrix;
    uint8_t nextState;
};

inline void applyTransition(
    Matrix& H,
    const Matrix& T
)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    const uint64_t ta = T.a;
    const uint64_t tb = T.b;
    const uint64_t tc = T.c;
    const uint64_t td = T.d;

    Matrix result;

    result.a = addMod(
        reduce(static_cast<u128>(a) * ta),
        reduce(static_cast<u128>(b) * tc)
    );

    result.b = addMod(
        reduce(static_cast<u128>(a) * tb),
        reduce(static_cast<u128>(b) * td)
    );

    result.c = addMod(
        reduce(static_cast<u128>(c) * ta),
        reduce(static_cast<u128>(d) * tc)
    );

    result.d = addMod(
        reduce(static_cast<u128>(c) * tb),
        reduce(static_cast<u128>(d) * td)
    );

    H = result;
}

using TransitionTable =
std::array<
    std::array<Transition, 256>,
    16
>;

// Build the transition table using the currently selected P.
TransitionTable buildTransitionTable()
{
    if (P == 0)
    {
        throw std::runtime_error(
            "Initialize the modulus before building the table."
        );
    }

    TransitionTable table{};

    for (int startingState = 0;
        startingState < 16;
        ++startingState)
    {
        for (int byteValue = 0;
            byteValue < 256;
            ++byteValue)
        {
            Matrix transformation = {
                1, 0,
                0, 1
            };

            uint8_t state =
                static_cast<uint8_t>(startingState);

            uint8_t byte =
                static_cast<uint8_t>(byteValue);

            for (int bitPosition = 7;
                bitPosition >= 0;
                --bitPosition)
            {
                const uint8_t bit =
                    (byte >> bitPosition) & 1;

                processBit(
                    transformation,
                    state,
                    bit
                );
            }

            table[startingState][byteValue] = {
                transformation,
                state
            };
        }
    }

    return table;
}

// Build the table once, after modulus initialization.
const TransitionTable& getTransitionTable()
{
    if (P == 0)
    {
        throw std::runtime_error(
            "Initialize the modulus before hashing."
        );
    }

    static const TransitionTable table =
        buildTransitionTable();

    return table;
}

// ============================================================
// Hash output encoding
// ============================================================

inline void matrixToBytes(
    const Matrix& m,
    uint8_t* out
)
{
    const uint64_t vals[4] = {
        m.a,
        m.b,
        m.c,
        m.d
    };

    for (int i = 0; i < 4; ++i)
    {
        const uint64_t v = vals[i];

        out[i * 8 + 0] =
            static_cast<uint8_t>(v >> 56);

        out[i * 8 + 1] =
            static_cast<uint8_t>(v >> 48);

        out[i * 8 + 2] =
            static_cast<uint8_t>(v >> 40);

        out[i * 8 + 3] =
            static_cast<uint8_t>(v >> 32);

        out[i * 8 + 4] =
            static_cast<uint8_t>(v >> 24);

        out[i * 8 + 5] =
            static_cast<uint8_t>(v >> 16);

        out[i * 8 + 6] =
            static_cast<uint8_t>(v >> 8);

        out[i * 8 + 7] =
            static_cast<uint8_t>(v);
    }
}

// ============================================================
// Cayley hash
// ============================================================

void cayleyHash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    if (P == 0)
    {
        throw std::runtime_error(
            "Initialize the modulus before hashing."
        );
    }

    Matrix H = {
        1, 0,
        0, 1
    };

    uint8_t state = makeState(
        0,
        0,
        0
    );

    const TransitionTable& table =
        getTransitionTable();

    for (size_t i = 0; i < len; ++i)
    {
        const uint8_t byte = data[i];

        const Transition& transition =
            table[state][byte];

        applyTransition(
            H,
            transition.matrix
        );

        state = transition.nextState;
    }

    // Apply three zero-bit padding operations.
    mulA(H);
    mulA(H);
    mulA(H);

    matrixToBytes(H, out);
}