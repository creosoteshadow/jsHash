#pragma once
// file ChaChaEncryptor.h

#include <array>
#include <cstdint>
#include <cstring>
#include <bit>

namespace ChaCha {

    using ChaChaKey = std::array<uint32_t, 8>;   // 256-bit
    using ChaChaNonce = std::array<uint32_t, 3>;   // 96-bit

    class ChaCha20 {
        alignas(64) uint32_t state[16]{};     // full state (cache-line aligned!)
        alignas(64) uint32_t keystream[16]{};
        size_t keystream_pos = 64;            // force first generation
        uint64_t block_counter;

        static constexpr uint32_t sigma[4] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        };

    public:
        ChaCha20(const ChaChaKey& key, const ChaChaNonce& nonce, uint64_t initial_counter = 1)
        {
            block_counter = initial_counter;

            std::memcpy(state, sigma, 16);
            std::memcpy(state + 4, key.data(), 32);
            // IETF ChaCha20 (RFC 8439): 96-bit nonce
            //   state[12] = counter_lo
            //   state[13] = counter_hi
            //   state[14] = nonce[0]   (bits 0–31)
            //   state[15] = nonce[1]   (bits 32–63)
            //   → nonce[2] (bits 64–95) is intentionally ignored
            state[12] = static_cast<uint32_t>(block_counter);
            state[13] = static_cast<uint32_t>(block_counter >> 32);
            state[14] = nonce[0];
            state[15] = nonce[1];   // nonce[2] is ignored (IETF ChaCha20 – 96-bit nonce)
        }

        // Convenience: encrypt/decrypt in-place
        void crypt(uint8_t* data, size_t len) noexcept {
            xor_stream(data, data, len);
        }

        // one-shot API for 64 byte encrytion
        std::array<uint64_t, 8> encrypt_block(const std::array<uint64_t, 8>& block) noexcept {
            std::array<uint64_t, 8> result(block);
            crypt (reinterpret_cast<uint8_t*>(result.data()), 64);
            return result;
        }

    private:
        // Refill keystream when exhausted
        void refill_keystream() noexcept {
            uint32_t input[16];
            std::memcpy(input, state, 64);

            // 20 rounds (10 column + 10 diagonal)
            for (int r = 0; r < 10; ++r) {
                QR(input[0], input[4], input[8], input[12]);
                QR(input[1], input[5], input[9], input[13]);
                QR(input[2], input[6], input[10], input[14]);
                QR(input[3], input[7], input[11], input[15]);

                QR(input[0], input[5], input[10], input[15]);
                QR(input[1], input[6], input[11], input[12]);
                QR(input[2], input[7], input[8], input[13]);
                QR(input[3], input[4], input[9], input[14]);
            }

            for (int i = 0; i < 16; ++i)
                keystream[i] = input[i] + state[i];

            // Increment counter (64-bit!)
            ++block_counter;
            state[12] = uint32_t(block_counter);
            state[13] = uint32_t(block_counter >> 32);

            keystream_pos = 0;
        }

        // XOR arbitrary data with ChaCha20 stream
        void xor_stream(uint8_t* out, const uint8_t* in, size_t len) noexcept {
            while (len > 0) {
                if (keystream_pos >= 64)
                    refill_keystream();

                size_t take = std::min(len, 64 - keystream_pos);
                const uint8_t* ks = reinterpret_cast<const uint8_t*>(keystream) + keystream_pos;

                for (size_t i = 0; i < take; ++i)
                    out[i] = in[i] ^ ks[i];

                out += take;
                in += take;
                len -= take;
                keystream_pos += take;
            }
        }

        static inline void QR(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
            a += b; d ^= a; d = std::rotl(d, 16);
            c += d; b ^= c; b = std::rotl(b, 12);
            a += b; d ^= a; d = std::rotl(d, 8);
            c += d; b ^= c; b = std::rotl(b, 7);
        }
    };

} // namespace
