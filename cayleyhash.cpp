#include <cstdint>
#include <cstddef>
#include <boost/multiprecision/cpp_int.hpp>

#include <array>

using u128 = boost::multiprecision::uint128_t;

// Modulus p = 2^64 - 59
static constexpr uint64_t P = UINT64_MAX - 58;


// Matrix representation
struct Matrix {
    uint64_t a, b, c, d;
};

// Fast modular reduction
inline uint64_t reduce(u128 x)
{
    uint64_t low =
        static_cast<uint64_t>(x);

    uint64_t high =
        static_cast<uint64_t>(x >> 64);

    // Fold the upper 64 bits into the lower portion.
    u128 r =
        static_cast<u128>(low) +
        static_cast<u128>(high) * 59;

    uint64_t r_low =
        static_cast<uint64_t>(r);

    uint64_t r_high =
        static_cast<uint64_t>(r >> 64);

    // A second fold handles any bits produced above
    // the lower 64 bits.
    u128 r2 =
        static_cast<u128>(r_low) +
        static_cast<u128>(r_high) * 59;

    uint64_t result =
        static_cast<uint64_t>(r2);

    // Bring the result into the canonical range [0, P).
    if (result >= P)
        result -= P;

    return result;
}

// Matrix transformation A
inline void mulA(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t c = H.c;

    H.b =
        reduce(
            static_cast<u128>(a) * 2 +
            H.b
        );

    H.d =
        reduce(
            static_cast<u128>(c) * 2 +
            H.d
        );
}

// Matrix transformation B
inline void mulB(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    H.a =
        reduce(
            static_cast<u128>(a) +
            static_cast<u128>(b) * 2
        );

    H.b =
        reduce(
            static_cast<u128>(a) +
            b
        );

    H.c =
        reduce(
            static_cast<u128>(c) +
            static_cast<u128>(d) * 2
        );

    H.d =
        reduce(
            static_cast<u128>(c) +
            d
        );
}

// Matrix transformation C
inline void mulC(Matrix& H)
{
    const uint64_t a = H.a;
    const uint64_t b = H.b;
    const uint64_t c = H.c;
    const uint64_t d = H.d;

    H.a =
        reduce(
            static_cast<u128>(a) * 2 +
            b
        );

    H.b =
        reduce(
            static_cast<u128>(a) +
            b
        );

    H.c =
        reduce(
            static_cast<u128>(c) * 2 +
            d
        );

    H.d =
        reduce(
            static_cast<u128>(c) +
            d
        );
}

// ============================================================
// Hash state encoding
//
// The cookie mechanism tracks three pieces of information:
//
//     last_bit
//     streak
//     cookie_mode
//
// The streak only needs four states:
//
//     0 = no previous streak
//     1 = one consecutive bit
//     2 = two consecutive bits
//     3 = three or more consecutive bits
//
// The state is stored in one byte:
//
//     bit 0     = last_bit
//     bits 1-2  = streak
//     bit 3     = cookie_mode
//
// This gives 16 possible states.
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

// Decode a stored hash state into its individual components.
inline void decodeState(
    uint8_t state,
    uint8_t& lastBit,
    uint8_t& streak,
    uint8_t& cookieMode
)
{
    lastBit =
        state & 1;

    streak =
        (state >> 1) & 3;

    cookieMode =
        (state >> 3) & 1;
}

// ============================================================
// Update the cookie state for one input bit.
//
// A consecutive sequence of equal bits increases the streak.
// A different bit starts a new streak.
//
// Once three consecutive bits have been observed, cookie_mode
// becomes equal to the current bit.
// ============================================================

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

    if (bit == lastBit) {

        // A streak of three or more is represented by 3.
        if (streak < 3)
            ++streak;

    }
    else {

        // A different bit starts a new streak.
        streak = 1;
    }

    lastBit = bit;

    // Three consecutive equal bits activate cookie mode.
    if (streak >= 3)
        cookieMode = bit;

    return makeState(
        lastBit,
        streak,
        cookieMode
    );
}

// ============================================================
// Process one input bit.
//
// The cookie state determines whether transformation A, B,
// or C is applied to the current matrix.
// ============================================================

inline void processBit(
    Matrix& H,
    uint8_t& state,
    uint8_t bit
)
{
    state =
        processBitState(
            state,
            bit
        );

    uint8_t lastBit;
    uint8_t streak;
    uint8_t cookieMode;

    decodeState(
        state,
        lastBit,
        streak,
        cookieMode
    );

    if (!bit) {

        // Zero bits apply transformation A.
        mulA(H);

    }
    else if (cookieMode) {

        // One bits in cookie mode apply transformation C.
        mulC(H);

    }
    else {

        // One bits outside cookie mode apply transformation B.
        mulB(H);
    }
}

// ============================================================
// A transition contains:
//
//     matrix
//         Combined matrix transformation for one input byte.
//
//     nextState
//         Cookie state after processing that byte.
// ============================================================

struct Transition {
    Matrix matrix;
    uint8_t nextState;
};

// ============================================================
// Apply a precomputed matrix transformation.
//
// If the current hash matrix is H and the transition matrix
// is T, the resulting matrix is:
//
//     H' = H * T
//
// Matrix multiplication is performed modulo P.
// ============================================================

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

    result.a =
        reduce(
            static_cast<u128>(a) * ta +
            static_cast<u128>(b) * tc
        );

    result.b =
        reduce(
            static_cast<u128>(a) * tb +
            static_cast<u128>(b) * td
        );

    result.c =
        reduce(
            static_cast<u128>(c) * ta +
            static_cast<u128>(d) * tc
        );

    result.d =
        reduce(
            static_cast<u128>(c) * tb +
            static_cast<u128>(d) * td
        );

    H = result;
}

// ============================================================
// Transition table
//
// There are 16 possible cookie states and 256 possible byte
// values:
//
//     16 * 256 = 4096 transitions
//
// Each transition stores the combined effect of processing
// all eight bits of a byte and the resulting cookie state.
//
// The table is constructed once and then reused for every
// hash operation.
// ============================================================

using TransitionTable =
std::array<
    std::array<Transition, 256>,
    16
>;

// Build the byte transition table.
TransitionTable buildTransitionTable()
{
    TransitionTable table{};

    for (int startingState = 0;
        startingState < 16;
        ++startingState)
    {
        for (int byteValue = 0;
            byteValue < 256;
            ++byteValue)
        {
            // Identity matrix.
            Matrix transformation = {
                1, 0,
                0, 1
            };

            uint8_t state =
                static_cast<uint8_t>(
                    startingState
                    );

            uint8_t byte =
                static_cast<uint8_t>(
                    byteValue
                    );

            // Process the byte from the most significant
            // bit to the least significant bit.
            for (int bitPosition = 7;
                bitPosition >= 0;
                --bitPosition)
            {
                uint8_t bit =
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

// Return the transition table.
const TransitionTable& getTransitionTable()
{
    static const TransitionTable table =
        buildTransitionTable();

    return table;
}

// Convert the final 2x2 matrix into a 32-byte hash.
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

    for (int i = 0; i < 4; ++i) {

        uint64_t v = vals[i];

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

// Cayley hash, starting with the identity matrix.
//
// Each input byte is processed using the precomputed transition
// table. The table determines both the matrix transformation
// and the new cookie state.
//
// Three zero bits are then processed as padding, corresponding
// to three applications of transformation A.
//
// The final matrix is converted to the 32-byte hash output.

void cayleyHash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    // Initial hash matrix.
    Matrix H = {
        1, 0,
        0, 1
    };

    // Initial cookie state:
    //
    // last_bit   = 0
    // streak     = 0
    // cookie_mode = false
    uint8_t state =
        makeState(
            0,
            0,
            0
        );

    // Obtain the precomputed byte transition table.
    const TransitionTable& table =
        getTransitionTable();

    // Process each input byte.
    for (size_t i = 0; i < len; ++i)
    {
        const uint8_t byte = data[i];

        const Transition& transition =
            table[state][byte];

        // Apply the combined matrix transformation
        // corresponding to all eight bits of this byte.
        applyTransition(
            H,
            transition.matrix
        );

        // Update the cookie state.
        state =
            transition.nextState;
    }

    // Apply the three zero-bit padding operations.
    mulA(H);
    mulA(H);
    mulA(H);

    // Convert the final matrix into the 32-byte hash.
    matrixToBytes(
        H,
        out
    );
}