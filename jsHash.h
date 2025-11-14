#pragma once
// File jsHash.h

/*
file jsHash.h

Contains class jsHash, a fast dual mode hash function.
*/

#include <algorithm>    // std::min
#include <array>
#include <bit>          // std::rotl (C++20), fallback below
#include <cstddef>      // std::size_t
#include <cstdint>      // uint64_t
#include <cstring>      // memcpy, memset
#include <iostream>
#include <string>
#include <vector>
#include <type_traits>  // std::enable_if_t

#if defined(_MSC_VER)
#   include <intrin.h>  // _umul128, __cpuid
#endif

#include "ChaChaEncryptor.h"
#include "u128.h"

// #define EnforceStrictAliasing 0
// Set to 1 for strict C++ compliance (safer, uses memcpy, marginally slower)
// Set to 0 for maximum performance (common in xxHash, wyhash, etc.)
#define EnforceStrictAliasing 0


#if __cplusplus < 202002L
    // use portable rotation if std::rotl not available
inline constexpr uint64_t rotl(uint64_t x, int r) noexcept {
    return (x << r) | (x >> (64 - r));
}
#else
using std::rotl;
#endif


/*====================================================================*
jsHash – ultra-fast, keyed, streamable non-cryptographic hash

    • 15.7 GB/s bulk processing speed on a modern x86-64 CPU (single-thread)
    • Header-only, standard C++
    • Dual mode finalizationion
        • Standard: Returns 64, 128, or 256 bit hash values
        • Secure: 128, 256, and 512 bit, secured with ChaCha20 encryption
    • Excellent avalanche (≈32 bit flips per input bit)
    • Fully keyed – same data → different hash per seed

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
====================================================================*/

class jsHash {
private:
    /*----------------------------------------------------------------*
     *  Internal state
     *----------------------------------------------------------------*/
    uint64_t v[4] = { 0 };   // four independent lanes
    size_t   nbytes = 0;     // total bytes fed to insert()
    uint8_t buffer[32] = {};
    int buffer_index;

    /*----------------------------------------------------------------*
     *  Constants
     *----------------------------------------------------------------*/
    static constexpr uint64_t MIX = 0xbf58476d1ce4e5b9ULL;   // SplitMix64 mix
    static constexpr uint64_t PHI = 0x9e3779b97f4a7c15ULL;   // floor(2⁶⁴/φ)
    static constexpr uint64_t PHI2 = 0x6c62272e07bb0143ULL;  // another golden-ratio derived

public:
    /*----------------------------------------------------------------*
     *  Construction – key the hash
     *
     *  One user-supplied 64-bit seed is expanded with SplitMix64 into
     *  the four lane initials.  This gives a unique output per seed.
     *----------------------------------------------------------------*/
    explicit constexpr jsHash(uint64_t key = 42)
        : buffer_index(0)
    {
        SplitMix64 gen(key);
        v[0] = gen();
        v[1] = gen();
        v[2] = gen();
        v[3] = gen();
    }
    jsHash(const jsHash& other) {
        memcpy(v, other.v, 4 * sizeof(uint64_t));
        nbytes = other.nbytes;
        memcpy(buffer, other.buffer, 32);
        buffer_index = other.buffer_index;
    }

    /*----------------------------------------------------------------*
     *  Data insertion
     *
     *  Options here include an array of uint8_t's,
     *  std::vector's, std::array's, std::string's, and C-style strings.
     *----------------------------------------------------------------*/

     /*----------------------------------------------------------------*
      *  Incremental update – absorb arbitrary data
      *
      *  • 32-byte fast path (four 64-bit words) – fully parallel
      *  • 8-byte fallback
      *  • <8-byte tail
      *
      *  Each word is mixed into its dedicated lane; the lanes never
      *  touch each other until finalisation → maximum ILP.
      *----------------------------------------------------------------*/
    void insert(const uint8_t* x, size_t size) noexcept {
        if (size == 0) return;

        size_t remaining = size;
        const uint8_t* ptr = x;

        if (buffer_index > 0) {
            // If there is anything in the buffer, we will try to fill the buffer
            // and process it (if we have enough data to fill it).
            size_t needed = 32 - buffer_index;
            size_t take = std::min(needed, remaining);
            memcpy(buffer + buffer_index, ptr, take);
            buffer_index += (int)take;
            ptr += take;
            remaining -= take;

            if (buffer_index == 32) {
                process_buffer();
            }
        }

        // Buffer is now empty.

        // Fast path. Process bytes directly out of x. No buffer handling needed.
        while (remaining >= 32) {
            process_32bytes(ptr);
            ptr += 32;
            remaining -= 32;
        }

        // Tail - any bytes not yet consumed. Less than 32 bytes.
        if (remaining > 0) {
            memcpy(buffer, ptr, remaining);
            buffer_index = (int)remaining;
        }

        nbytes += size;  
        if (nbytes < size) { 
            // Overflow happened. But how in the world did we insert > 2^64 bytes? That would probably 
            // take nearly 40 years. Something seriously wrong must going one here.
            std::cout << "Fatal error: byte counter overflowed.\n";
            std::cout << "File = " << __FILE__ << "\n";
            std::cout << "Line = " << __LINE__ << "\n";
            system("pause");
            exit(EXIT_FAILURE);
        }
    }

    // std::vector<T>
    template <typename T>
    void insert(const std::vector<T>& data) noexcept
        requires std::is_trivially_copyable_v<T>
    {
        insert((uint8_t*)data.data(), data.size() * sizeof(T));
    }

    // std::array<T, N>
    template <typename T, std::size_t N>
    void insert(const std::array<T, N>& data) noexcept
        requires std::is_trivially_copyable_v<T>
    {
        insert((uint8_t*)data.data(), N * sizeof(T));
    }

    // Insert std::string
    void insert(const std::string& s) noexcept {
        insert((uint8_t*)s.data(), s.size());
    }

    // Insert C style string
    void insert(const char* str) noexcept {
        insert((uint8_t*)str, std::strlen(str));
    }


    /*----------------------------------------------------------------*
     *  Finalise → 256-bit hash value
     *
     *  3 options
     *      hash256() - returns a 256 bit hash value
     *      hash128() - returns a 128 bit hash value
     *      hash64()  - returns a 64 bit hash value
     *----------------------------------------------------------------*/

    std::array<uint64_t, 4>
        hash256() const
    {
        jsHash temp(*this);

        // Process any remaining data in the buffer
        if (temp.buffer_index > 0) {
            std::memset(temp.buffer + temp.buffer_index, 0, 32 - temp.buffer_index); // zero pad
            temp.buffer_index = 32; // we filled with zeros. 32 indicates buffer is full, so process_buffer() will succeed.
            temp.process_buffer(); // now buffer_index == 0
        }

        // 1. copy lanes to local variables
        uint64_t a = temp.v[0], b = temp.v[1], c = temp.v[2], d = temp.v[3];

        // 2. length injection
        a = mix(a, temp.nbytes);                       // low 32 bits
        b = mix(b, temp.nbytes >> 32);                 // high 32 bits

        // 3. seasoning (prevents zero-lane bias)
        c = mix(c, PHI);
        d = mix(d, PHI2);

        // 4. cross-channel avalanche
        uint64_t t;
        t = mix(a, b); a ^= t; b ^= rotl(t, 11);
        t = mix(c, d); c ^= t; d ^= rotl(t, 23);
        t = mix(a, d); a ^= t; d ^= rotl(t, 31);
        t = mix(b, c); b ^= t; c ^= rotl(t, 43);

        return { a, b, c, d };
    }

    std::array<uint64_t, 2>
        hash128() const {
        std::array<uint64_t, 4> h256 = hash256();
        return { h256[0] ^ h256[1], h256[2] ^ h256[3] };
    }

    uint64_t
        hash64() const {
        std::array<uint64_t, 4> h256 = hash256();
        return h256[0] ^ h256[1] ^ h256[2] ^ h256[3];
    }

    // NEW: Finalize with encryption
    template <size_t N>
    std::array<uint64_t, N> hash_secure(
        const ChaCha::ChaChaKey& key,
        const ChaCha::ChaChaNonce& nonce = ChaCha::ChaChaNonce{} // default zero nonce
    ) const noexcept
    {
        // 1. Finalize the fast part into raw state (same as in hash256())
        jsHash h(*this); // copy
        
        if (h.buffer_index > 0) {
            // zero pad, then process any bytes remaining in the buffer
            std::memset(h.buffer + h.buffer_index, 0, 32 - h.buffer_index); // zero pad
            h.buffer_index = 32; // we filled with zeros. 32 indicates buffer is full, so process_buffer() will succeed.
            h.process_buffer(); 
        }

        // 2. Build the block
        std::array<uint64_t, 8> block{};
        // Instead of using the final mixing of hash256, we use the values in the lanes, 'v[]'.
        block[0] = h.v[0]; // insert the 4 lanes into block
        block[1] = h.v[1];
        block[2] = h.v[2];
        block[3] = h.v[3];
        // simple expansion, use nbytes and constants
        block[4] = h.nbytes; // insert the byte counter
        block[5] = h.nbytes >> 32;
        block[6] = 0x517cc1b727220a94ULL;   // Insert constants. domain constant (golden ratio conj.)
        block[7] = 0x853a83b0eba87773ULL;   // more salt

        // 3. Perform ChaCha20 encryption on the block
        ChaCha::ChaCha20 encryptor(key, nonce);
        auto ciphertext = encryptor.encrypt_block(block);

        // 4. Truncate to requested size (compile-time safe)
        std::array<uint64_t, N> result{};
        static_assert(N <= 8, "jsHash only supports up to 512-bit secure output");
        std::memcpy(result.data(), ciphertext.data(), N * 8);
        return result;
    }

    // Convenience aliases
    auto hash512_secure(const ChaCha::ChaChaKey& k, const ChaCha::ChaChaNonce& n = {}) const noexcept {
        return hash_secure<8>(k, n);
    }
    auto hash256_secure(const ChaCha::ChaChaKey& k, const ChaCha::ChaChaNonce& n = {}) const noexcept {
        return hash_secure<4>(k, n);
    }
    auto hash128_secure(const ChaCha::ChaChaKey& k, const ChaCha::ChaChaNonce& n = {}) const noexcept {
        return hash_secure<2>(k, n);
    }
private:

    /*----------------------------------------------------------------*
     *  Core mixing primitive – 128-bit multiply + fold
     *
     *  a * (b ^ MIX) → (hi:lo) → a ^ b ^ lo ^ hi
     *  Gives fast performance and good avalanche.
     *----------------------------------------------------------------*/
    static inline uint64_t mix(uint64_t a, uint64_t b) noexcept {
#if defined(_MSC_VER)
        uint64_t hi, lo;
        lo = _umul128(a, b ^ MIX, &hi);
        return a ^ b ^ lo ^ hi;
#elif defined(__SIZEOF_INT128__)
        __uint128_t p = (__uint128_t)a * (b ^ MIX);
        return a ^ b ^ (uint64_t)p ^ (p >> 64);
#else
        // Portable fallback: ~2–3× slower, but correct
        u128::u128 p = mul64_portable(a, b ^ MIX);
        return a ^ b ^ p.lo ^ p.hi;
#endif
    }

    // Attempt to insert n bytes into the buffer.
    // Returns number of bytes inserted
    inline int insert_into_buffer(const uint8_t* data, size_t n)
    {
        size_t available_space = 32ull - buffer_index;
        int bytes_to_insert = (int)std::min(available_space, n);
        memcpy(buffer + buffer_index, data, bytes_to_insert);
        buffer_index += bytes_to_insert;
        return bytes_to_insert;
    }

    inline void zero_pad_buffer() noexcept {
        if (buffer_index < 32)
            std::memset(buffer + buffer_index, 0, 32 - buffer_index);
        buffer_index = 32;
    }

    inline bool is_buffer_full()const {
        return buffer_index == 32;
    }


    inline void process_buffer() {
        if (buffer_index < 32) return;
        process_32bytes(buffer);
        buffer_index = 0;
    }

#if EnforceStrictAliasing
    inline uint64_t load64(const uint8_t* p) noexcept {
        uint64_t w;
        std::memcpy(&w, p, sizeof(w));
        return w;
    }
    inline void process_32bytes(const uint8_t* p) noexcept {
        v[0] = mix(v[0], load64(p + 0));
        v[1] = mix(v[1], load64(p + 8));
        v[2] = mix(v[2], load64(p + 16));
        v[3] = mix(v[3], load64(p + 24));
    }
#else
    inline void process_32bytes(const uint8_t* p) noexcept {
        const uint64_t* src = reinterpret_cast<const uint64_t*>(p);

        v[0] = mix(v[0], src[0]);
        v[1] = mix(v[1], src[1]);
        v[2] = mix(v[2], src[2]);
        v[3] = mix(v[3], src[3]);
    }
#endif


    // SplitMix64 is used in the constructor.
    class SplitMix64 {
        uint64_t state;
    public:
        constexpr SplitMix64(uint64_t initial_state) :state(initial_state) {}
        inline constexpr uint64_t operator()() noexcept {
            uint64_t z = (state += 0x9e3779b97f4a7c15);
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
            z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
            return z ^ (z >> 31);
        }
    };

    // for use in portable version of the mix() function
    // 128-bit product of two 64-bit unsigned integers, done portably
    // using only 64-bit arithmetic (no __int128 or compiler intrinsics).
    inline constexpr u128::u128 mul64_portable(uint64_t a, uint64_t b) noexcept {
        const auto LO = [](uint64_t x) { return x & 0xFFFFFFFFULL; };
        const auto HI = [](uint64_t x) { return x >> 32; };

        const uint64_t p00 = LO(a) * LO(b);
        const uint64_t p01 = LO(a) * HI(b);
        const uint64_t p10 = HI(a) * LO(b);
        const uint64_t p11 = HI(a) * HI(b);

        const uint64_t x = HI(p00) + LO(p01) + LO(p10);
        const uint64_t y = HI(p01) + HI(p10) + LO(p11) + HI(x);

        return {
            LO(p00) | (x << 32),          // lower 64 bits. (x<<32) keeps low bits, high bits are already in y.
            y + (HI(p11) << 32)           // upper 64 bits with final carry
        };
    }

};

/*----------------------------------------------------------------*
   1-liner API for standard usage

       uint64_t key = 50;
       uint64_t x[] = { 1ull, 2ull, 3ull };

       uint64_t x_hash = jsHash(key)(x,sizeof(x));

       std::cout << "x_hash = " << x_hash << "\n";
 ----------------------------------------------------------------*/
[[nodiscard]] uint64_t Hash64(const void* p, size_t n, const uint64_t seed = 42) {
    jsHash h(seed);
    h.insert(static_cast<const uint8_t*>(p), n);
    return h.hash64();
}

/*----------------------------------------------------------------*
   1-liner API for secure usage

        ChaCha::ChaChaKey key{ 1,2,3,4,5,6,7,8 };
        ChaCha::ChaChaNonce nonce{ 1,2,3,4 };
        uint64_t x[] = { 1ull, 2ull, 3ull };
        auto result = jsHash(42).SecureHash( x, sizeof(x), key, nonce);
 ----------------------------------------------------------------*/
template<size_t N = 4>
[[nodiscard]] inline auto SecureHash(
    const void* data, size_t len,
    const ChaCha::ChaChaKey& key,
    uint64_t seed = 42,
    const ChaCha::ChaChaNonce& nonce = {})
{
    jsHash h(seed);
    h.insert(static_cast<const uint8_t*>(data), len);
    return h.hash_secure<N>(key, nonce);
}
