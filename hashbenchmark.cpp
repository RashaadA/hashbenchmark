#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>
#include <random>
#include <iomanip>
#include <cstdint>
#include <algorithm>
#include <string>
#include <cstdio>
#include <stdexcept>
#include <limits>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "blake3.h"
#include "cayleyhash.h"

using namespace std;

// ============================================================
// Hash functions
// ============================================================

// Cayley hash.
void cayley_hash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    cayleyHash(data, len, out);
}

// SHA-256.
void sha256_hash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    SHA256(data, len, out);
}

// SHA-3.
void sha3_hash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (ctx == nullptr)
    {
        throw runtime_error(
            "Failed to allocate SHA-3 context."
        );
    }

    unsigned int outputLength = 0;

    if (EVP_DigestInit_ex(
        ctx,
        EVP_sha3_256(),
        nullptr
    ) != 1)
    {
        EVP_MD_CTX_free(ctx);

        throw runtime_error(
            "Failed to initialize SHA-3."
        );
    }

    if (EVP_DigestUpdate(
        ctx,
        data,
        len
    ) != 1)
    {
        EVP_MD_CTX_free(ctx);

        throw runtime_error(
            "Failed to process SHA-3 input."
        );
    }

    if (EVP_DigestFinal_ex(
        ctx,
        out,
        &outputLength
    ) != 1)
    {
        EVP_MD_CTX_free(ctx);

        throw runtime_error(
            "Failed to finalize SHA-3."
        );
    }

    EVP_MD_CTX_free(ctx);

    if (outputLength != 32)
    {
        throw runtime_error(
            "Unexpected SHA-3 output length."
        );
    }
}

// BLAKE3.
void blake3_hash(
    const uint8_t* data,
    size_t len,
    uint8_t* out
)
{
    blake3_hasher hasher;

    blake3_hasher_init(&hasher);

    blake3_hasher_update(
        &hasher,
        data,
        len
    );

    blake3_hasher_finalize(
        &hasher,
        out,
        BLAKE3_OUT_LEN
    );
}

// ============================================================
// Hash output conversion
// ============================================================

// Convert hash bytes to hexadecimal.
string hashToHex(
    const uint8_t* hash,
    size_t length
)
{
    string result;

    result.reserve(length * 2);

    for (size_t i = 0; i < length; i++)
    {
        char buffer[3];

        snprintf(
            buffer,
            sizeof(buffer),
            "%02x",
            hash[i]
        );

        result += buffer;
    }

    return result;
}

// ============================================================
// Benchmarking
// ============================================================

void benchmark(
    const string& name,
    void (*hashf)(
        const uint8_t*,
        size_t,
        uint8_t*
        ),
    const vector<uint8_t>& data,
    int iterations,
    ofstream& outputFile
)
{
    uint8_t out[32] = {};

    // Warmup phase.
    const int warmup = min(100, iterations);

    for (int i = 0; i < warmup; i++)
    {
        hashf(
            data.data(),
            data.size(),
            out
        );
    }

    // Timed benchmarking phase.
    auto start =
        chrono::steady_clock::now();

    for (int i = 0; i < iterations; i++)
    {
        hashf(
            data.data(),
            data.size(),
            out
        );
    }

    auto end =
        chrono::steady_clock::now();

    const double ms =
        chrono::duration<double, milli>(
            end - start
        ).count();

    // Throughput in MiB/s.
    const double totalBytes =
        static_cast<double>(data.size()) *
        iterations;

    const double throughput =
        totalBytes /
        (ms / 1000.0) /
        (1024.0 * 1024.0);

    // Calculate the final output for recording.
    hashf(
        data.data(),
        data.size(),
        out
    );

    const string hashHex =
        hashToHex(out, sizeof(out));

    // Display results.
    cout << name
        << " | "
        << data.size()
        << " bytes | "
        << fixed << setprecision(3)
        << ms
        << " ms | "
        << throughput
        << " MiB/s\n";

    outputFile << name
        << " | "
        << data.size()
        << " bytes | "
        << fixed << setprecision(3)
        << ms
        << " ms | "
        << throughput
        << " MiB/s\n";

    outputFile << "Hash output: "
        << hashHex
        << "\n\n";
}

// ============================================================
// Iteration selection
// ============================================================

int choose_iterations(size_t size)
{
    if (size <= 1024)
        return 500;

    if (size <= 10 * 1024)
        return 250;

    if (size <= 100 * 1024)
        return 100;

    if (size <= 1024 * 1024)
        return 50;

    if (size <= 10 * 1024 * 1024)
        return 5;

    return 5;
}

// ============================================================
// Input generation
// ============================================================

// Generate reproducible random input.
vector<uint8_t> generateRandomInput(size_t size)
{
    vector<uint8_t> data(size);

    mt19937_64 generator(123456789);

    for (size_t i = 0; i < size; i++)
    {
        data[i] = static_cast<uint8_t>(
            generator() & 0xFF
            );
    }

    return data;
}

// ============================================================
// Input saving
// ============================================================

// Save input bytes as hexadecimal text.
void saveInputAsText(
    const vector<uint8_t>& data,
    const string& filename
)
{
    ofstream file(filename);

    if (!file)
    {
        throw runtime_error(
            "Could not open " + filename
        );
    }

    file << "Random benchmark input\n";
    file << "Size: "
        << data.size()
        << " bytes\n";

    file << "Seed: 123456789\n\n";
    file << "Data (hex):\n";

    for (size_t i = 0; i < data.size(); i++)
    {
        file << hex
            << setw(2)
            << setfill('0')
            << static_cast<unsigned int>(data[i]);

        if (i + 1 < data.size())
            file << ' ';

        if ((i + 1) % 32 == 0)
            file << '\n';
    }

    file << '\n';

    if (!file)
    {
        throw runtime_error(
            "Failed while writing " + filename
        );
    }
}

// ============================================================
// Main benchmark program
// ============================================================

int main()
{
    try
    {
        // Select or load the Cayley modulus before hashing.
        initializeCayleyHashModulus();

        const uint64_t modulus =
            getCayleyHashModulus();

        cout << "\nUsing Cayley modulus: "
            << modulus << "\n\n";

        // Benchmark sizes.
        const vector<size_t> sizes = {
            1024,
            10 * 1024,
            100 * 1024,
            1024 * 1024,
            10 * 1024 * 1024,
            100 * 1024 * 1024
        };

        // Generate one input for all tests.
        const size_t maxSize = sizes.back();

        cout << "Generating "
            << maxSize / (1024 * 1024)
            << " MiB of random input...\n";

        const vector<uint8_t> randomInput =
            generateRandomInput(maxSize);

        cout << "Random input generated.\n";

        // Save the complete input.
        cout << "Writing input to input.txt...\n";

        saveInputAsText(
            randomInput,
            "input.txt"
        );

        cout << "Input saved to input.txt.\n\n";

        // Open benchmark output file.
        ofstream outputFile("output.txt");

        if (!outputFile)
        {
            throw runtime_error(
                "Could not create output.txt"
            );
        }

        // Record benchmark configuration.
        outputFile
            << "Hash Benchmark Results\n"
            << "======================\n\n";

        outputFile
            << "Random input seed: 123456789\n"
            << "Cayley modulus: "
            << modulus << '\n';

        outputFile
            << "All hash functions use the same input bytes.\n"
            << "Cayley output length: 32 bytes\n"
            << "SHA-256 output length: 32 bytes\n"
            << "SHA-3 output length: 32 bytes\n"
            << "BLAKE3 output length: 32 bytes\n\n";

        outputFile
            << "Hash function | Input Size | Time (ms) "
            << "| Throughput (MiB/s)\n\n";

        cout
            << "Hash function | Input Size | Time (ms) "
            << "| Throughput (MiB/s)\n\n";

        // Run the benchmarks.
        for (size_t size : sizes)
        {
            const int iterations =
                choose_iterations(size);

            // Each benchmark size uses a prefix of the same input.
            vector<uint8_t> data(
                randomInput.begin(),
                randomInput.begin() + size
            );

            cout << "Input size: "
                << size
                << " bytes ("
                << iterations
                << " iterations)\n";

            outputFile << "Input size: "
                << size
                << " bytes ("
                << iterations
                << " iterations)\n";

            // SHA-256.
            benchmark(
                "SHA-256",
                sha256_hash,
                data,
                iterations,
                outputFile
            );

            // SHA-3.
            benchmark(
                "SHA-3",
                sha3_hash,
                data,
                iterations,
                outputFile
            );

            // BLAKE3.
            benchmark(
                "BLAKE3",
                blake3_hash,
                data,
                iterations,
                outputFile
            );

            // Cayley hash.
            benchmark(
                "Cayley hash",
                cayley_hash,
                data,
                iterations,
                outputFile
            );

            cout << '\n';
            outputFile << '\n';
        }

        outputFile.close();

        cout << "Benchmark complete.\n";
        cout << "Input saved to: input.txt\n";
        cout << "Results saved to: output.txt\n";
        cout << "Cayley modulus: "
            << modulus << '\n';
    }
    catch (const exception& e)
    {
        cerr << "Error: "
            << e.what() << '\n';

        return 1;
    }

    return 0;
}