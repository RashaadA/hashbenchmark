#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>
#include <random>
#include <iomanip>
#include <cstdint>
#include <algorithm>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "blake3.h"
#include "cayleyhash.h"

using namespace std;

// Cayley hash
void cayley_hash(const uint8_t* data, size_t len, uint8_t* out) {
    cayleyHash(data, len, out);
}

// SHA-256
void sha256_hash(const uint8_t* data, size_t len, uint8_t* out) {
    SHA256(data, len, out);
}

// SHA-3
void sha3_hash(const uint8_t* data, size_t len, uint8_t* out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);

    EVP_MD_CTX_free(ctx);
}

// BLAKE-3
void blake3_hash(const uint8_t* data, size_t len, uint8_t* out) {
    blake3_hasher newhash;

    blake3_hasher_init(&newhash);
    blake3_hasher_update(&newhash, data, len);
    blake3_hasher_finalize(&newhash, out, BLAKE3_OUT_LEN);
}

// Convert hash output to hexadecimal
string hashToHex(const uint8_t* hash, size_t length) {
    string result;

    for (size_t i = 0; i < length; i++) {
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

// Benchmark a hash function
void benchmark(
    const string& name,
    void (*hashf)(const uint8_t*, size_t, uint8_t*),
    const vector<uint8_t>& data,
    int iterations,
    ofstream& outputFile
) {
    uint8_t out[32];

    // Warmup phase
    int warmup = min(100, iterations);

    for (int i = 0; i < warmup; i++) {
        hashf(data.data(), data.size(), out);
    }

    // Timed benchmarking phase
    auto start = chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        hashf(data.data(), data.size(), out);
    }

    auto end = chrono::high_resolution_clock::now();

    double ms =
        chrono::duration<double, milli>(end - start).count();

    // Throughput in MB/s
    double throughput =
        (data.size() * iterations)
        / (ms / 1000.0)
        / (1024.0 * 1024.0);

    // Output results
    cout << name << " | "
        << data.size() << " bytes | "
        << ms << " ms | "
        << throughput << " MB/s\n";

    outputFile << name << " | "
        << data.size() << " bytes | "
        << ms << " ms | "
        << throughput << " MB/s\n";
}

// Number of iterations based on input size
int choose_iterations(size_t size) {
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

// Generate random input. Uses a fixed seed so the experiment is reproducible.
vector<uint8_t> generateRandomInput(size_t size) {

    vector<uint8_t> data(size);

    // Fixed seed for reproducibility
    mt19937_64 generator(123456789);

    // Generate random bytes
    for (size_t i = 0; i < size; i++) {
        data[i] = static_cast<uint8_t>(generator() & 0xFF);
    }

    return data;
}

// Save random input as hexadecimal text; Produces a text file containing the exact bytes used by the benchmark.
void saveInputAsText(
    const vector<uint8_t>& data,
    const string& filename
) {
    ofstream file(filename);

    if (!file) {
        cerr << "Error: Could not open "
            << filename << endl;

        return;
    }

    file << "Random benchmark input\n";
    file << "Size: " << data.size() << " bytes\n";
    file << "Seed: 123456789\n\n";

    file << "Data (hex):\n";

    for (size_t i = 0; i < data.size(); i++) {

        file << hex
            << setw(2)
            << setfill('0')
            << static_cast<int>(data[i]);

        // Add a space between bytes
        if (i + 1 < data.size())
            file << " ";

        // New line every 32 bytes
        if ((i + 1) % 32 == 0)
            file << "\n";
    }

    file << "\n";

    file.close();
}

int main() {

    // Benchmark sizes
    const vector<size_t> sizes = {
        1024,                   // 1 KB
        10 * 1024,              // 10 KB
        100 * 1024,             // 100 KB
        1024 * 1024,            // 1 MB
        10 * 1024 * 1024,       // 10 MB
        100 * 1024 * 1024       // 100 MB
    };

    // Generate one random input large enough for all tests. Every smaller benchmark uses a prefix of this same input.
    const size_t maxSize = sizes.back();

    cout << "Generating "
        << maxSize / (1024 * 1024)
        << " MB of random input...\n";

    vector<uint8_t> randomInput =
        generateRandomInput(maxSize);

    cout << "Random input generated.\n";

    // Save input to text file
    cout << "Writing input to input.txt...\n";

    saveInputAsText(
        randomInput,
        "input.txt"
    );

    cout << "Input saved to input.txt.\n\n";

    // Open output file
    ofstream outputFile("output.txt");

    if (!outputFile) {
        cerr << "Error: Could not create output.txt\n";
        return 1;
    }

    outputFile << "Hash Benchmark Results\n";
    outputFile << "======================\n\n";

    outputFile << "Random input seed: 123456789\n";
    outputFile << "All hash functions use the same input data.\n\n";

    outputFile << "Hash function | Input Size | Time (ms) | "
        "Throughput (MB/s)\n\n";

    cout << "Hash function | Input Size | Time (ms) | "
        "Throughput (MB/s)\n\n";

    // Run benchmarks
    for (size_t size : sizes) {

        int iterations = choose_iterations(size);

        // All four hash functions receive EXACTLY the same vector for this input size.
        // We use the first 'size' bytes of the single randomly generated input.
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

        // SHA-256
        benchmark(
            "SHA-256",
            sha256_hash,
            data,
            iterations,
            outputFile
        );

        // SHA-3
        benchmark(
            "SHA-3",
            sha3_hash,
            data,
            iterations,
            outputFile
        );

        // BLAKE3
        benchmark(
            "BLAKE3",
            blake3_hash,
            data,
            iterations,
            outputFile
        );

        // Cayley hash
        benchmark(
            "Cayley hash",
            cayley_hash,
            data,
            iterations,
            outputFile
        );

        cout << "\n";
        outputFile << "\n";
    }

    outputFile.close();

    cout << "Benchmark complete.\n";
    cout << "Input saved to: input.txt\n";
    cout << "Results saved to: output.txt\n";

    return 0;
}