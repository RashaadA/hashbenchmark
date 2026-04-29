#include <iostream>
#include <vector>
#include <chrono>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "blake3.h"
#include "cayleyhash.h"

using namespace std;


// Cayley hash:
void cayley_hash(const uint8_t* data, size_t len, uint8_t* out) {
    cayleyHash(data, len, out);
}

// SHA-256:
void sha256_hash(const uint8_t* data, size_t len, uint8_t* out) {
    SHA256(data, len, out);
}

// SHA-3 (https://wiki.openssl.org/index.php/EVP_Message_Digests):
void sha3_hash(const uint8_t* data, size_t len, uint8_t* out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, NULL);
    EVP_MD_CTX_free(ctx);
}

//BLAKE-3 (https://github.com/BLAKE3-team/BLAKE3/blob/master/c/README.md):
void blake3_hash(const uint8_t* data, size_t len, uint8_t* out) {
    blake3_hasher newhash;
    blake3_hasher_init(&newhash);
    blake3_hasher_update(&newhash, data, len);
    blake3_hasher_finalize(&newhash, out, BLAKE3_OUT_LEN); // provides default length which is 32

}

void benchmark(const string& name, void (*hashf)(const uint8_t*, size_t, uint8_t*),
    const vector<uint8_t>& data, int iterations) 
{

    //output buffer
    uint8_t out[32];


	// Warmup phase to mitigate "cold-start" effects
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

    double ms = chrono::duration<double, milli>(end - start).count();
    // converting to seconds, calculating throughput in MB/s
    double throughput = (data.size() * iterations) / (ms / 1000.0) / (1024 * 1024);

    cout << name << " | "
        << data.size() << " bytes | "
        << ms << " ms | "
        << throughput << " MB/s\n";
}

// Number of iterations to run depending on the size of the input
int choose_iterations(size_t size) {
    if (size <= 1024) return 1000;
    if (size <= 10 * 1024) return 500;
    if (size <= 100 * 1024) return 100;
    if (size <= 1024 * 1024) return 50;
    return 10;
}

int main()
{


    vector<size_t> sizes = { 1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024, 100 * 1024 * 1024 };
    // Sizes: 1 KB, 10 KB, 100 KB, 1 MB, 10 MB, 100 MB

    cout << "Hash function | Input Size | Time (ms) | Throughput (MB/s)\n";

    for (size_t size : sizes) {
        vector<uint8_t> data(size, 0);

        cout << "\nInput size: " << size << " bytes\n";

        benchmark("SHA-256", sha256_hash, data, choose_iterations(size));
        benchmark("SHA-3", sha3_hash, data, choose_iterations(size));
        benchmark("BLAKE3", blake3_hash, data, choose_iterations(size));
        benchmark("Cayley hash", cayley_hash, data, choose_iterations(size));

    }

    cout << endl;
}