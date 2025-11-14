// file test_jsHash.cpp
// This file performs a test of the jsHash hashing class.

#define NOMINMAX // don't use min and max macros, included in <Windows.h>

#include "jsHash.h"

#include <array> 
#include <chrono>
#include <iomanip>
#include <iostream>
#include <random>
#include <unordered_set>

#include <Windows.h> // SetThreadAffinityMask, SetPriorityClass

// Function to pin current thread to CPU a core
void pin_to_core(int core) {
    DWORD_PTR affinity_mask = 1ULL << core;
    DWORD_PTR previous_mask = SetThreadAffinityMask(GetCurrentThread(), affinity_mask);
    if (previous_mask == 0) {
        std::cerr << "Failed to set thread affinity!\n";
    }
    else {
        std::cout << "Thread pinned to CPU core " << core << ".\n";
    }
}

// Upgrades the priority of the current process and the current thread.
void set_high_priority() {
    //if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
    if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS)) {
        std::cerr << "Failed to set process priority!\n";
    }
    else {
        //std::cout << "Process priority set to HIGH.\n";
    }

    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL)) {
        std::cerr << "Failed to set thread priority!\n";
    }
    else {
        //std::cout << "Thread priority set to TIME_CRITICAL.\n";
    }
}

/*
Full output from this test function, 11/12/2025, 01:15 AM
System: Processor	Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz, 3000 Mhz, 8 Core(s), 8 Logical Processor(s)
Compiler: MSVC 
Compiler command line: /permissive- /ifcOutput "test_Hash64\x64\Release\" /GS /GL /W3 /Gy /Zc:wchar_t /Zi /Gm- /O2 /sdl /Fd"test_Hash64\x64\Release\vc143.pdb" /Zc:inline /fp:precise /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /errorReport:prompt /WX- /Zc:forScope /std:clatest /Gd /Oi /MD /std:c++latest /FC /Fa"test_Hash64\x64\Release\" /EHsc /nologo /Fo"test_Hash64\x64\Release\" /FAs /Fp"test_Hash64\x64\Release\test_Hash64.pch" /diagnostics:column /Zc:__cplusplus 

Determinism test:
        828560291680242088      828560291680242088
        Pass

Non-commutative test:
        Pass

Avalanche test:
        Average bit difference = 32.0077
        Pass

Thread pinned to CPU core 0.
Hashed 68.719 GB in 4.353 s, 15.787 GB/s
Thread pinned to CPU core 1.
Hashed 68.719 GB in 4.352 s, 15.790 GB/s
Thread pinned to CPU core 2.
Hashed 68.719 GB in 4.365 s, 15.743 GB/s
Thread pinned to CPU core 3.
Hashed 68.719 GB in 4.354 s, 15.783 GB/s
Thread pinned to CPU core 4.
Hashed 68.719 GB in 4.371 s, 15.720 GB/s
Thread pinned to CPU core 5.
Hashed 68.719 GB in 4.361 s, 15.758 GB/s
Thread pinned to CPU core 6.
Hashed 68.719 GB in 4.362 s, 15.756 GB/s
Thread pinned to CPU core 7.
Hashed 68.719 GB in 4.365 s, 15.743 GB/s

Collision resistance test (1000000 samples):
        Pass: No collisions (expected ~0.0000000271 by birthday paradox)

Uniformity test (chi^2 on high byte):
        chi^2 = 278.8292608000 (threshold ~336 for p=0.001)
        Pass

Seed sensitivity test (1M consecutive seeds):
        Average bit difference = 32.0084740000
        Pass

Incremental vs bulk test:
        Pass

Edge cases:
        Empty hash: 13546448014017083291
        insert(nullptr,0) == default: Pass
        Single byte repeatable: Pass
*/


inline void test_hash64() {
    // Check determinism
    if (1) {
        jsHash A(200);
        jsHash B(200);
        std::byte a = std::byte(1);
        A.insert((uint8_t*)& a, 1);
        B.insert((uint8_t*)&a, 1);
        uint64_t ra = A.hash64();
        uint64_t rb = B.hash64();
        std::cout << "Determinism test:\n";
        std::cout << "\t" << ra << "\t" << rb << "\n";
        std::cout << "\t" << ((ra == rb) ? "Pass\n" : "Fail");
    }

    std::cout << "\n";
    // Check non-commutative property
    if (1) {
        jsHash A(200);
        jsHash B(200);
        std::byte a = std::byte(1);
        std::byte b = std::byte(2);
        A.insert((uint8_t*)&a, 1); A.insert((uint8_t*)&b, 1); uint64_t ha = A.hash64();
        B.insert((uint8_t*)&b, 1); B.insert((uint8_t*)&a, 1); uint64_t hb = B.hash64();
        std::cout << "Non-commutative test:\n";
        std::cout << "\t" << ((ha != hb) ? "Pass\n" : "Fail");
    }

    std::cout << "\n";
    // Check avalanche
    if (1) {
        std::mt19937_64 mt(54321);

        constexpr size_t nruns = 1000000;
        double sum = 0.0;
        for (size_t run = 0; run < nruns; run++) {
            jsHash A(200);
            jsHash B(200);

            uint64_t y = mt();
            int bitnum = mt() & 63;
            uint64_t z = y ^ (1ull << bitnum);

            A.insert((uint8_t*)&y, 8);
            B.insert((uint8_t*)&z, 8);

            uint64_t ha = A.hash64();
            uint64_t hb = B.hash64();

            int diff = std::popcount(ha ^ hb);
            sum += diff;
        }
        double average = sum / nruns;
        std::cout << "Avalanche test:\n";
        std::cout << "\tAverage bit difference = " << average << "\n";
        std::cout << "\t" << (((average > 31.9) && (average < 32.1)) ? "Pass" : "Fail") << "\n";
    }

    std::cout << "\n";
    // PERFORMANCE: Determine hasher throughput
    if (1)
        for (int core = 0; core <= 7; ++core)
        {
            pin_to_core(core);
            set_high_priority();

            constexpr size_t TARGET_BYTES = 64ull * 1024ull * 1024ull * 1024ull;  // 64 GB
            constexpr size_t CHUNK_BYTES = 64ull * 1024ull;                // 64 KB per chunk
            constexpr size_t CHUNK_WORDS = CHUNK_BYTES/sizeof(uint64_t);
            
            std::array<uint64_t, CHUNK_WORDS> buffer;

            // ---- fill the buffer with reproducible random data -----------------
            std::mt19937_64 mt(54321);
            for (auto& v : buffer) v = mt();

            const size_t LOOPS = TARGET_BYTES / CHUNK_BYTES;   // integer division

            jsHash hasher(42);

            // ---- high-resolution timer -----------------------------------------
            using clock = std::chrono::high_resolution_clock;
            const auto t0 = clock::now();

            for (size_t i = 0; i < LOOPS; ++i) {
                hasher.insert((uint8_t*)(buffer.data()), CHUNK_BYTES);
            }

            const auto t1 = clock::now();

            // ---- force the compiler to keep the hash result --------------------
            uint64_t dummy = hasher.hash64();
            if (dummy == 0) std::cout << "unexpected zero\n";

            // ---- compute elapsed time in seconds (double) ----------------------
            const std::chrono::duration<double> elapsed = t1 - t0;
            const double seconds = elapsed.count();

            const double gigabytes = static_cast<double>(TARGET_BYTES) / (1e9);
            const double gigabytes_s = gigabytes / seconds;

            std::cout << std::fixed << std::setprecision(3)
                << "Hashed " << gigabytes << " GB in "
                << seconds << " s, "
                << gigabytes_s << " GB/s\n";
        }

    std::cout << "\n";
    // test_collision_resistance
    if (1) {
        constexpr size_t N = 1'000'000;
        std::unordered_set<uint64_t> seen;
        jsHash hasher(12345);
        std::mt19937_64 rng(9876);

        bool collision_found = false;
        uint64_t a_val = 0, b_val = 0;

        for (size_t i = 0; i < N && !collision_found; ++i) {
            uint64_t x = rng();
            hasher = jsHash(12345); // same seed
            hasher.insert((uint8_t*)&x, 8);
            uint64_t h = hasher.hash64();

            if (seen.count(h)) {
                collision_found = true;
                // Try to find the colliding input
                for (uint64_t prev = 0; prev < x; ++prev) {
                    hasher = jsHash(12345); // same seed
                    hasher.insert((uint8_t*)&prev, 8);
                    if (hasher.hash64() == h) {
                        a_val = prev; b_val = x;
                        break;
                    }
                }
            }
            seen.insert(h);
        }

        std::cout << "Collision resistance test (" << N << " samples):\n";
        if (collision_found) {
            std::cout << "\tFAIL: Collision found: " << a_val << " vs " << b_val << "\n";
        }
        else {
            double expected_collisions = (double)N * N / (2.0 * pow(2., 64.));
            std::cout << "\tPass: No collisions (expected ~" << std::fixed << std::setprecision(10)
                << expected_collisions << " by birthday paradox)\n";
        }
    }

    std::cout << "\n";
    // test_uniformity
    if (1) {
        constexpr size_t SAMPLES = 10'000'000;
        std::vector<uint64_t> counts(256, 0);
        jsHash hasher(777);
        std::mt19937_64 rng(12345);

        for (size_t i = 0; i < SAMPLES; ++i) {
            uint64_t x = rng();
            hasher = jsHash(777);
            hasher.insert((uint8_t*)&x, 8);
            uint64_t h = hasher.hash64();
            counts[(h >> 56) & 0xFF]++;  // Use top byte for simplicity
        }

        double expected = SAMPLES / 256.0;
        double chi2 = 0.0;
        for (auto c : counts) {
            double diff = c - expected;
            chi2 += diff * diff / expected;
        }

        // Critical value for χ²(255) at p=0.001 ≈ 336
        std::cout << "Uniformity test (chi^2 on high byte):\n";
        std::cout << "\tchi^2 = " << chi2 << " (threshold ~336 for p=0.001)\n";
        std::cout << "\t" << (chi2 < 336 ? "Pass" : "Fail") << "\n";
    }

    std::cout << "\n";
    // test_seed_sensitivity – robust, high-confidence
    if (1) {
        std::mt19937_64 mt(54321);
        constexpr size_t nruns = 1'000'000;
        double sum = 0.0;
        uint64_t input = mt();  // fixed message

        for (size_t run = 0; run < nruns; ++run) {
            jsHash A(run);
            jsHash B(run + 1);
            A.insert((uint8_t*)&input, 8);
            B.insert((uint8_t*)&input, 8);
            uint64_t ha = A.hash64();
            uint64_t hb = B.hash64();
            sum += std::popcount(ha ^ hb);
        }
        double avg = sum / nruns;

        std::cout << "Seed sensitivity test (1M consecutive seeds):\n";
        std::cout << "\tAverage bit difference = " << avg << "\n";
        std::cout << "\t" << ((avg > 31.9 && avg < 32.1) ? "Pass" : "Fail") << "\n";
    }

    std::cout << "\n";
    // test bulk/incremental_equivalence 
    if (1) {
        std::mt19937_64 mt(999);
        std::vector<std::byte> data(1024);
        for (auto& b : data) b = std::byte(mt() & 0xFF);

        // Bulk
        jsHash h1(111);
        h1.insert((uint8_t*)data.data(), data.size());
        uint64_t bulk = h1.hash64();

        // Incremental
        jsHash h2(111);
        for (size_t i = 0; i < data.size(); i += 7) {
            size_t chunk = std::min<size_t>(7, data.size() - i);
            h2.insert((uint8_t*)data.data() + i, chunk);
        }
        uint64_t inc = h2.hash64();

        std::cout << "Incremental vs bulk test:\n";
        std::cout << "\t" << (bulk == inc ? "Pass" : "Fail") << "\n";
    }

    std::cout << "\n";
    //test_edge_cases
    if (1) {
        std::cout << "Edge cases:\n";

        jsHash h1(0);
        std::cout << "\tEmpty hash: " << h1.hash64() << "\n";

        jsHash h2(0);
        h2.insert(nullptr, 0);
        bool empty_ok = (h1.hash64() == h2.hash64());
        std::cout << "\tinsert(nullptr,0) == default: " << (empty_ok ? "Pass" : "Fail") << "\n";

        std::byte single_byte = std::byte(0xFF);
        jsHash h3(1), h4(1);
        h3.insert((uint8_t*)&single_byte, 1);
        h4.insert((uint8_t*)&single_byte, 1);
        std::cout << "\tSingle byte repeatable: " << (h3.hash64() == h4.hash64() ? "Pass" : "Fail") << "\n";
    }
}


#if 1
int main() {
    test_hash64();
    return EXIT_SUCCESS;
}
#endif

