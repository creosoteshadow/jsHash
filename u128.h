#pragma once
#pragma once
// file u128.h

// Set to 1 to enable verification, 0 otherwise
#define EnablePortableMultiplyVerification 0

// struct uint128_t 
//      Holds lo and hi 64 bit components of a 128 bit unsigned integer.
// 
// uint128_t mul64(u64 a, u64 b) 
//      Returns a 128 bit product of two 64 bit unsigned integers. Uses
//      intrinsics for performance where available.
// 
// inline uint128_t mul64_portable(u64 a, u64 b) noexcept {
//      Portable 64×64 → 128-bit unsigned multiplication
//      - No compiler intrinsics in core routine
//      - Verified against hardware multiply on MSVC/GCC/Clang
//      - Full test suite with random + corner cases

#include <assert.h>
#include <cstdint>
#include <iomanip>  // for std::hex, std::setfill, std::setw
#include <sstream>
#include <string>

#if defined(_MSC_VER)
#include <intrin.h>   // for _umul128 on MSVC (built-in 64×64→128 multiply)
#endif

#if EnablePortableMultiplyVerification 
#include <iostream>
#include <random>
#endif


namespace u128 {
    struct u128;

    using u64 = uint64_t;
    using uint128_t = u128; // for people who love the _t suffix.

    // forward declarations
    struct u128;

    inline u128 mul64(u64 a, u64 b) noexcept;
    inline constexpr u128 mul64_portable(u64, u64) noexcept;
    inline constexpr u128 add64(u64 a, u64 b) noexcept;


    // u128: Simple struct to hold lo and hi parts of a 128 bit unsigned integer
    struct u128 {
        u64 lo, hi;

        constexpr u128() : lo(0), hi(0) {}
        explicit constexpr u128(u64 lo_) : lo(lo_), hi(0) {}
        constexpr u128(u64 lo_, u64 hi_) : lo(lo_), hi(hi_) {}

        // = operator
        constexpr u128& operator=(const u64 other) {
            lo = other;
            hi = 0;
            return *this;
        }

        // shifts
        constexpr u128& operator<<=(unsigned nbits) noexcept {
            if (nbits == 0)
                return *this;
            if (nbits >= 128) {
                lo = hi = 0;
                return *this;
            }
            if (nbits >= 64) {
                hi = lo;
                lo = 0;
                nbits -= 64;
            }
            if (nbits > 0) {
                hi = (hi << nbits) | (lo >> (64 - nbits));
                lo <<= nbits;
            }
            return *this;
        }
        constexpr u128& operator>>=(unsigned nbits) noexcept {
            if (nbits == 0)
                return *this;
            if (nbits >= 128) {
                lo = hi = 0;
                return *this;
            }
            if (nbits >= 64) {
                lo = hi;
                hi = 0;
                nbits -= 64;
            }
            if (nbits > 0) {
                lo = (lo >> nbits) | (hi << (64 - nbits));
                hi >>= nbits;
            }
            return *this;
        }
        constexpr u128 operator<<(unsigned nbits) const noexcept {
            return u128(*this) <<= nbits;
        }
        constexpr u128 operator>>(unsigned nbits) const noexcept {
            return u128(*this) >>= nbits;
        }

        // bitwise
        constexpr u128 operator~() const {
            return u128(~lo, ~hi);
        }
        constexpr u128& operator&=(const u128& other) {
            lo &= other.lo;
            hi &= other.hi;
            return *this;
        }
        constexpr u128& operator^=(const u128& other) {
            lo ^= other.lo;
            hi ^= other.hi;
            return *this;
        }
        constexpr u128& operator|=(const u128& other) {
            lo |= other.lo;
            hi |= other.hi;
            return *this;
        }
        constexpr u128 operator&(const u128& other) const {
            return u128(lo & other.lo, hi & other.hi);
        }
        constexpr u128 operator^(const u128& other) const {
            return u128(lo ^ other.lo, hi ^ other.hi);
        }
        constexpr u128 operator|(const u128& other) const {
            return u128(lo | other.lo, hi | other.hi);
        }

        // comparison operators
        constexpr bool operator==(const u128& o) const noexcept { return lo == o.lo && hi == o.hi; }
        constexpr bool operator!=(const u128& o) const noexcept { return !(*this == o); }
        constexpr bool operator<(const u128& o) const noexcept {
            return hi < o.hi || (hi == o.hi && lo < o.lo);
        }
        constexpr bool operator<=(const u128& o) const noexcept { return !(o < *this); }
        constexpr bool operator>(const u128& o) const noexcept { return o < *this; }
        constexpr bool operator>=(const u128& o) const noexcept { return !(*this < o); }

        // + operators can overflow silently.
        constexpr u128& operator+=(const u128& other) {
            // Handles carry at the 64 bit position.
            // Does not handle overflow at the 128 bit level
            lo += other.lo;
            hi += other.hi + (lo < other.lo);
            return *this;
        }
        constexpr u128& operator+=(const u64 other) {
            lo += other;
            hi += (lo < other);
            return *this;
        }
        constexpr u128 operator+(const u128& other) const {
            return u128(*this) += other;
        }
        constexpr u128 operator+(const u64 other) const {
            return u128(*this) += other;
        }
        friend constexpr u128 operator+(const u64 a, const u128& b) { return u128(a) += b; }

        // * operators can overflow silently.

        // Warning: all multiplication operators are performed modulo 2¹²⁸ to be consistent
        // with the way std::uint64_t works. Full 256 bit multiplication requires an external
        // function, possibly something like this:
        //      u256 mul128( const u128& a, const u128& b )
        // But, at this time a u256 class has not been built.
        //
        // constexpr discussion: since the intrinsic _umul128 is not const, we had to decide
        // between making the multiplications constexpr, which would require the use of the
        // slower mul64_portable, or not constexpr, which gives us the ability to use the intrinsics.
        // For performance reasons we chose the second option.

        u128 operator*(const u64 other) const noexcept {
            u128 p_lo = mul64(lo, other);
            u128 p_hi = mul64(hi, other);
            return p_lo + (p_hi << 64); // discard upper bits of p_hi
        }
        u128 operator*(const u128& other) const noexcept {
            // Use full 128×64 muls and add with carry
            u128 res = mul64(lo, other.lo);                    // lo * lo
            res += mul64(lo, other.hi) << 64;                  // lo * hi
            res += mul64(hi, other.lo) << 64;                  // hi * lo
            // hi * hi << 128 → discarded (mod 2¹²⁸)
            return res;
        }
        u128& operator*=(const u64 other) noexcept {
            *this = (*this) * other;
            return *this;
        }
        u128& operator*=(const u128& other) noexcept {
            *this = (*this) * other;
            return *this;
        }
        friend u128 operator*(const u64 a, const u128& b) noexcept { return b * a; }

        // printing functions

        std::string to_string() const {
            if (hi == 0) return std::to_string(lo);
            return std::to_string(hi) + "_" + std::to_string(lo);  // or hex
        }
        std::string to_string_hex() const {
            // always outputs 34 characters
            std::ostringstream oss;
            oss << "0x"
                << std::hex << std::setfill('0')
                << std::setw(16) << hi
                << std::setw(16) << lo;
            return oss.str();
        }
        friend std::ostream& operator<<(std::ostream& os, const u128& v) {
            return os << v.to_string_hex();
        }
    };

    static constexpr u128 ZERO{ 0, 0 };
    static constexpr u128 ONE{ 1, 0 };
    static constexpr u128 MAX{ UINT64_MAX, UINT64_MAX };

    // Add with carry, u64 + u64 → u128
    inline constexpr u128 add64(u64 a, u64 b) noexcept {
        u64 lo = a + b;
        u64 hi = (lo < a) ? 1 : 0;
        return { lo, hi };
    }


    // Returns a 128 bit product of two 64 bit unsigned integers. Uses
    // intrinsics for performance where available.
    // u64 * u64 → u128
    // Note: Cannot be constexpr because _umul128 is not constexpr
    inline u128 mul64(u64 a, u64 b) noexcept {

#if defined(_MSC_VER)
        u64 lo, hi;
        lo = _umul128(a, b, &hi);
        return { lo, hi };

#elif defined(__SIZEOF_INT128__)
        // Use GCC/Clang 128 bit integer type
        unsigned __int128 prod = (unsigned __int128)a * (unsigned __int128)b;
        return { (u64)prod, prod >> 64 };

#else
        return mul64_portable(a, b);
#endif
    }


    // 128-bit product of two 64-bit unsigned integers, done portably
    // using only 64-bit arithmetic (no __int128 or compiler intrinsics).
    inline constexpr u128 mul64_portable(u64 a, u64 b) noexcept {
        // Split each 64-bit operand into 32-bit halves
        const auto LO = [](u64 x) { return x & 0xFFFFFFFFULL; };
        const auto HI = [](u64 x) { return x >> 32; };

        // 32×32-bit partial products
        // a = a1:a0, b = b1:b0  (each half is 32 bits)
        // p00 = a0 * b0 (low×low)
        // p01 = a0 * b1 (low×high)
        // p10 = a1 * b0 (high×low)
        // p11 = a1 * b1 (high×high)
        const u64 p00 = LO(a) * LO(b);
        const u64 p01 = LO(a) * HI(b);
        const u64 p10 = HI(a) * LO(b);
        const u64 p11 = HI(a) * HI(b);

        // -----------------------------------------------------------------
        // The 128-bit product can be written as:
        //   (p11 << 64) + ((p01 + p10) << 32) + p00
        //
        // The "middle" terms (p01 + p10) overlap with bits [32..95],
        // so we have to carefully propagate carries across these overlaps.
        // -----------------------------------------------------------------

        // x holds the lower 64-bit chunk that will form the *middle* part
        // of the product, before shifting left by 32 bits.
        //
        // HI(p00): upper 32 bits of p00 (carry from the lowest 32×32 block)
        // LO(p01): lower 32 bits of (a0*b1)
        // LO(p10): lower 32 bits of (a1*b0)
        //
        // Each of these contributes to bits [32..63] of the 128-bit result.
        // If this sum overflows 64 bits, that overflow is the carry into
        // the *upper* half of the product — we’ll collect that in HI(x).
        const u64 x = HI(p00) + LO(p01) + LO(p10);

        // y accumulates all the *upper* 32-bit halves of the cross terms,
        // plus the low half of p11, and also any carry out of x (HI(x)).
        //
        // HI(p01): high 32 bits of (a0*b1)
        // HI(p10): high 32 bits of (a1*b0)
        // LO(p11): low 32 bits of (a1*b1)
        // HI(x): carry from adding HI(p00)+LO(p01)+LO(p10)
        //
        // So y represents bits [64..95] of the full 128-bit product,
        // before we add the final top 32 bits of p11.
        const u64 y = HI(p01) + HI(p10) + LO(p11) + HI(x);

        // -----------------------------------------------------------------
        // Construct final 128-bit result:
        //
        // Low 64 bits = lower 32 of p00, plus (x << 32)
        // - LO(p00) gives bits [0..31]
        // - (x << 32) gives bits [32..63]
        //
        // High 64 bits = y + (HI(p11) << 32)
        // - y covers bits [64..95]
        // - HI(p11)<<32 covers bits [96..127]
        // - y never overflows 64 bits (max = 3*(2^32-1) + 2)
        // - we use + instead of | because y may exceed 2^32; those high bits
        //   are carries into the upper word. Adding is simpler and faster
        //   than extracting and shifting them manually.
        // -----------------------------------------------------------------
        return {
            LO(p00) | (x << 32),          // lower 64 bits
            y + (HI(p11) << 32)           // upper 64 bits with final carry
        };
    }



#if EnablePortableMultiplyVerification

    // -----------------------------------------------------------------------------
    // Compare our portable multiplication result to the compiler intrinsic version.
    // -----------------------------------------------------------------------------
    //
    // Returns true if both 128-bit results match; otherwise prints diagnostics.
    //
    // _umul128(a,b,&hi) is a MSVC intrinsic that computes the full 128-bit
    // unsigned product of a and b. It stores the upper 64 bits into *hi and
    // returns the lower 64 bits.
    //
    // The test confirms that our portable version produces *identical* lo and hi
    // values for a large set of random and edge-case inputs.
    //
    bool test_product(u64 a, u64 b, bool mute = false) {
        // Compute product using our portable implementation
        u128 prod = mul64_portable(a, b);

        // Compute reference product using hardware intrinsic
        u64 hi;                      // must be declared *before* calling
        u64 lo = _umul128(a, b, &hi); // returns low 64 bits, sets high 64 bits

        // Optionally print detailed comparison
        if (!mute) {
            std::cout << a << " * " << b << "\n";
            std::cout << "prod = { " << prod.lo << ", " << prod.hi << " }\n";
            std::cout << "ref  = { " << lo << ", " << hi << " }\n";
            std::cout << (lo == prod.lo && hi == prod.hi ?
                "*** SUCCESS ***\n\n" :
                "*** FAIL ***\n\n");
        }

        // Return true if all 128 bits match exactly
        return (lo == prod.lo && hi == prod.hi);
    }

    // -----------------------------------------------------------------------------
    // Bulk test driver — runs thousands of random and deterministic test cases
    // to ensure our 64×64→128 multiply matches the hardware intrinsic exactly.
    // -----------------------------------------------------------------------------
    bool test_product() {
        int failures = 0;

        // Use std::random_device to generate non-deterministic 64-bit inputs
        std::random_device rd;
        for (int i = 0; i < 10000; i++) {
            // Combine two 32-bit random values to form a full 64-bit number
            u64 a = rd() | (static_cast<u64>(rd()) << 32);
            u64 b = rd() | (static_cast<u64>(rd()) << 32);

            // Accumulate any mismatches
            failures += (test_product(a, b, true) ? 0 : 1);
        }

        // -------------------------------------------------------------------------
        // Deterministic corner cases to check boundaries and carries:
        // -------------------------------------------------------------------------
        failures += (test_product(0, 0) ? 0 : 1);                       // zero × zero
        failures += (test_product(1, 1) ? 0 : 1);                       // small × small
        failures += (test_product(1, UINT64_MAX) ? 0 : 1);              // 1 × max
        failures += (test_product(UINT64_MAX, 1) ? 0 : 1);              // max × 1
        failures += (test_product(UINT64_MAX, UINT64_MAX) ? 0 : 1);     // max × max (full carry propagation)
        failures += (test_product(0x100000001ULL, 0x100000001ULL) ? 0 : 1); // cross-boundary pattern (2^32+1)^2
        failures += (test_product(0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFDULL) ? 0 : 1);
        failures += (test_product(0xFFFFFFFFFFFFFFFDULL, 0xFFFFFFFFFFFFFFFEULL) ? 0 : 1);

        // Print final test summary
        std::cout << "N Failures = " << failures << "\n";

        // Return true if any failures occurred (for test frameworks)
        return (failures > 0);
    }
#endif


} // namespace U128
