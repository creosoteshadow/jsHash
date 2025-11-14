jsHash – ultra-fast, keyed, streamable non-cryptographic hash

    • 15.7 GB/s bulk processing speed on a modern x86-64 CPU (single-thread)
    • Header-only, standard C++
    • Dual mode finalizationion
        • Standard: Returns 64, 128, or 256 bit hash values
        • Secure: 128, 256, and 512 bit, secured with ChaCha20 encryption
    • Excellent avalanche (≈32 bit flips per input bit)
    • Fully keyed – same data → different hash per seed

Easy to use -- just include "jsHash.h"
    
    #include <cstdint>
    #include <iostream>
    #include "jsHash.h"
    
    int main() {
        uint64_t key = 54321;
        jsHash Hasher(key);
    
        Hasher.insert(std::string("This is my input data."));
        uint64_t hashval = Hasher.hash64();
    
        std::cout << "hashval = " << hashval << "\n";
    
        return EXIT_SUCCESS;
    }

Security Notice

    While this hash has a secure mode, a true cryptographic
    has has undergone extensive industry review that this one has not. For
    _guaranteed_ security in a hash function, use a routine that has
    undergone this extensive review process. Consider using BLAKE3 or KMAC
    for applications needing cryptographic quality hashing.

Design (four parallel lanes):
    
    • lane0 … lane3  ←  independent 64-bit accumulators
    each 32-byte input block is split into four 64-bit words
    word_i  →  lane_i  via a high-quality 128→64 fold (mix)
    • Core mixing function is based on _umul128; very similar
    to wyrand.
    • Finalisation folds the message length, adds seasoning constants,
    cross-mixes the lanes, and XOR-folds the result. Optionally, finalization
    routines are available to encrypt the hash results.

User Interface
    
    • Constructor
        jsHash(uint64_t key)
    • Data insertion
        void insert(const uint8_t* data, size_t n)
        template <typename T> void insert(const std::vector<T>& data)
        template <typename T, std::size_t N> void insert(const std::array<T, N>& data)
        void insert(std::string sv)
        void insert(const char* str)
    • Finalization
        Normal Mode
            std::array<uint64_t, 4> hash256()
            std::array<uint64_t, 2> hash128();
            uint64_t jsHash()
        Secure Mode
            auto hash128_secure(key, nonce)
            auto hash256_secure(key, nonce)
            auto hash512_secure(key, nonce)
    • 1-liner API
        Standard mode, non-member function
            uint64_t Hash64(const void* p, size_t n, const uint64_t seed = 42)
        Secure Mode, non-member function
            template<size_t N = 4> [[nodiscard]] inline auto
            SecureHash(
                const void* data, size_t len,
                const ChaCha::ChaChaKey& key,
                uint64_t seed = 42,
                const ChaCha::ChaChaNonce& nonce = {});

Limitations
    
    - This hash function will generate securely generated hash
      values, but takes an unconventional approach. For applications
      that require guaranteed security, use a hash function that has
      been validated by the cryptographic community.
    - This hash function has not been tested against SMHasher.
    - The core mix() function relies on the Windows-only 128-bit
      multiplication intrinsic, _umul128, or the gnu __uint128_t.
        The portable fallback is much slower.

Programming notes

    1) The finalization functions cannot be made constexpr, since they rely
        on the _umul128 intrinsic which is not constexpr.
    2) For gcc/Clang, calls to _umul128 have been replaced with use of
        the __int128 type. This should have equivalent performance.
    3) A portable implementation is in place for unrecognized compilers.
        This is likely 3-4X slower than the intrinsic version.

Test results:

    See separate file test_jsHash for code and results.

License

    [MIT License](LICENSE) – free for commercial use, modification, distribution, and private use.

    


