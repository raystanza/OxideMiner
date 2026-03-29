//! RandomX-specific pseudo-random generators and AES-based hash utilities.

use crate::aes::{aes_round_decrypt, aes_round_encrypt};
use crate::blake::hash512;
use crate::flags::RandomXFlags;

/// AES-based generator used for 1-round RandomX AES mixing.
pub struct AesGenerator1R {
    state: [u8; 64],
}

impl AesGenerator1R {
    /// Create a generator seeded with 64 bytes.
    pub fn new(seed: [u8; 64]) -> Self {
        Self { state: seed }
    }

    /// Advance the generator and return the next 64-byte block.
    pub fn next(&mut self, flags: &RandomXFlags) -> [u8; 64] {
        for i in 0..4 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.state[i * 16..(i + 1) * 16]);
            match i {
                0 => aes_round_decrypt(&mut block, &AES_GEN1R_KEYS[0], flags),
                1 => aes_round_encrypt(&mut block, &AES_GEN1R_KEYS[1], flags),
                2 => aes_round_decrypt(&mut block, &AES_GEN1R_KEYS[2], flags),
                3 => aes_round_encrypt(&mut block, &AES_GEN1R_KEYS[3], flags),
                _ => {}
            }
            self.state[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }
        self.state
    }

    /// Return the current internal state.
    pub fn state(&self) -> [u8; 64] {
        self.state
    }
}

/// AES-based generator used for 4-round RandomX AES mixing.
pub struct AesGenerator4R {
    state: [u8; 64],
}

impl AesGenerator4R {
    /// Create a generator seeded with 64 bytes.
    pub fn new(seed: [u8; 64]) -> Self {
        Self { state: seed }
    }

    /// Replace the internal state.
    pub fn set_state(&mut self, seed: [u8; 64]) {
        self.state = seed;
    }

    /// Advance the generator and return the next 64-byte block.
    pub fn next(&mut self, flags: &RandomXFlags) -> [u8; 64] {
        for col in 0..4 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.state[col * 16..(col + 1) * 16]);
            let key_offset = if col < 2 { 0 } else { 4 };
            for round in 0..4 {
                let key = &AES_GEN4R_KEYS[key_offset + round];
                if col % 2 == 0 {
                    aes_round_decrypt(&mut block, key, flags);
                } else {
                    aes_round_encrypt(&mut block, key, flags);
                }
            }
            self.state[col * 16..(col + 1) * 16].copy_from_slice(&block);
        }
        self.state
    }
}

/// Streaming AES-based hash used by RandomX.
pub struct AesHash1R {
    state: [u8; 64],
}

impl AesHash1R {
    /// Create a new streaming hash instance.
    pub fn new() -> Self {
        Self {
            state: AES_HASH1R_STATE,
        }
    }

    /// Incorporate a 64-byte block into the hash state.
    pub fn update(&mut self, block: &[u8; 64], flags: &RandomXFlags) {
        for col in 0..4 {
            let key = &block[col * 16..(col + 1) * 16];
            let mut state_col = [0u8; 16];
            state_col.copy_from_slice(&self.state[col * 16..(col + 1) * 16]);
            if col % 2 == 0 {
                aes_round_encrypt(&mut state_col, array16(key), flags);
            } else {
                aes_round_decrypt(&mut state_col, array16(key), flags);
            }
            self.state[col * 16..(col + 1) * 16].copy_from_slice(&state_col);
        }
    }

    /// Finalize and return the hash value.
    pub fn finalize(mut self, flags: &RandomXFlags) -> [u8; 64] {
        for key in AES_HASH1R_XKEYS.iter() {
            for col in 0..4 {
                let mut state_col = [0u8; 16];
                state_col.copy_from_slice(&self.state[col * 16..(col + 1) * 16]);
                if col % 2 == 0 {
                    aes_round_encrypt(&mut state_col, key, flags);
                } else {
                    aes_round_decrypt(&mut state_col, key, flags);
                }
                self.state[col * 16..(col + 1) * 16].copy_from_slice(&state_col);
            }
        }
        self.state
    }
}

/// Blake2b-based generator used for program generation.
pub struct BlakeGenerator {
    state: [u8; 64],
    offset: usize,
}

impl BlakeGenerator {
    /// Create a new generator seeded with arbitrary bytes.
    pub fn new(seed: &[u8]) -> Self {
        let mut buf = [0u8; 64];
        let len = seed.len().min(60);
        buf[..len].copy_from_slice(&seed[..len]);
        let state = hash512(&buf);
        Self { state, offset: 0 }
    }

    pub fn next_u8(&mut self) -> u8 {
        if self.offset >= 64 {
            self.state = hash512(&self.state);
            self.offset = 0;
        }
        let out = self.state[self.offset];
        self.offset += 1;
        out
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.offset + 4 > 64 {
            self.state = hash512(&self.state);
            self.offset = 0;
        }
        let bytes = [
            self.state[self.offset],
            self.state[self.offset + 1],
            self.state[self.offset + 2],
            self.state[self.offset + 3],
        ];
        self.offset += 4;
        u32::from_le_bytes(bytes)
    }
}

fn array16(slice: &[u8]) -> &[u8; 16] {
    slice.try_into().expect("slice length must be 16")
}

/// Compute the RandomX AES 1-round hash for an arbitrary input.
pub fn aes_hash_1r(input: &[u8], flags: &RandomXFlags) -> [u8; 64] {
    let mut hasher = AesHash1R::new();
    let mut block = [0u8; 64];
    for chunk in input.chunks(64) {
        block.fill(0);
        block[..chunk.len()].copy_from_slice(chunk);
        hasher.update(&block, flags);
    }
    hasher.finalize(flags)
}

const AES_GEN1R_KEYS: [[u8; 16]; 4] = [
    [
        0x53, 0xa5, 0xac, 0x6d, 0x09, 0x66, 0x71, 0x62, 0x2b, 0x55, 0xb5, 0xdb, 0x17, 0x49, 0xf4,
        0xb4,
    ],
    [
        0x07, 0xaf, 0x7c, 0x6d, 0x0d, 0x71, 0x6a, 0x84, 0x78, 0xd3, 0x25, 0x17, 0x4e, 0xdc, 0xa1,
        0x0d,
    ],
    [
        0xf1, 0x62, 0x12, 0x3f, 0xc6, 0x7e, 0x94, 0x9f, 0x4f, 0x79, 0xc0, 0xf4, 0x45, 0xe3, 0x20,
        0x3e,
    ],
    [
        0x35, 0x81, 0xef, 0x6a, 0x7c, 0x31, 0xba, 0xb1, 0x88, 0x4c, 0x31, 0x16, 0x54, 0x91, 0x16,
        0x49,
    ],
];

const AES_GEN4R_KEYS: [[u8; 16]; 8] = [
    [
        0xdd, 0xaa, 0x21, 0x64, 0xdb, 0x3d, 0x83, 0xd1, 0x2b, 0x6d, 0x54, 0x2f, 0x3f, 0xd2, 0xe5,
        0x99,
    ],
    [
        0x50, 0x34, 0x0e, 0xb2, 0x55, 0x3f, 0x91, 0xb6, 0x53, 0x9d, 0xf7, 0x06, 0xe5, 0xcd, 0xdf,
        0xa5,
    ],
    [
        0x04, 0xd9, 0x3e, 0x5c, 0xaf, 0x7b, 0x5e, 0x51, 0x9f, 0x67, 0xa4, 0x0a, 0xbf, 0x02, 0x1c,
        0x17,
    ],
    [
        0x63, 0x37, 0x62, 0x85, 0x08, 0x5d, 0x8f, 0xe7, 0x85, 0x37, 0x67, 0xcd, 0x91, 0xd2, 0xde,
        0xd8,
    ],
    [
        0x73, 0x6f, 0x82, 0xb5, 0xa6, 0xa7, 0xd6, 0xe3, 0x6d, 0x8b, 0x51, 0x3d, 0xb4, 0xff, 0x9e,
        0x22,
    ],
    [
        0xf3, 0x6b, 0x56, 0xc7, 0xd9, 0xb3, 0x10, 0x9c, 0x4e, 0x4d, 0x02, 0xe9, 0xd2, 0xb7, 0x72,
        0xb2,
    ],
    [
        0xe7, 0xc9, 0x73, 0xf2, 0x8b, 0xa3, 0x65, 0xf7, 0x0a, 0x66, 0xa9, 0x2b, 0xa7, 0xef, 0x3b,
        0xf6,
    ],
    [
        0x09, 0xd6, 0x7c, 0x7a, 0xde, 0x39, 0x58, 0x91, 0xfd, 0xd1, 0x06, 0x0c, 0x2d, 0x76, 0xb0,
        0xc0,
    ],
];

const AES_HASH1R_STATE: [u8; 64] = [
    0x0d, 0x2c, 0xb5, 0x92, 0xde, 0x56, 0xa8, 0x9f, 0x47, 0xdb, 0x82, 0xcc, 0xad, 0x3a, 0x98, 0xd7,
    0x6e, 0x99, 0x8d, 0x33, 0x98, 0xb7, 0xc7, 0x15, 0x5a, 0x12, 0x9e, 0xf5, 0x57, 0x80, 0xe7, 0xac,
    0x17, 0x00, 0x77, 0x6a, 0xd0, 0xc7, 0x62, 0xae, 0x6b, 0x50, 0x79, 0x50, 0xe4, 0x7c, 0xa0, 0xe8,
    0x0c, 0x24, 0x0a, 0x63, 0x8d, 0x82, 0xad, 0x07, 0x05, 0x00, 0xa1, 0x79, 0x48, 0x49, 0x99, 0x7e,
];

const AES_HASH1R_XKEYS: [[u8; 16]; 2] = [
    [
        0x89, 0x83, 0xfa, 0xf6, 0x9f, 0x94, 0x24, 0x8b, 0xbf, 0x56, 0xdc, 0x90, 0x01, 0x02, 0x89,
        0x06,
    ],
    [
        0xd1, 0x63, 0xb2, 0x61, 0x3c, 0xe0, 0xf4, 0x51, 0xc6, 0x43, 0x10, 0xee, 0x9b, 0xf9, 0x18,
        0xed,
    ],
];

#[cfg(test)]
mod tests {
    use super::{AesGenerator1R, AesGenerator4R, AesHash1R, BlakeGenerator};
    use crate::flags::RandomXFlags;

    #[test]
    fn aes_generators_are_deterministic() {
        let flags = RandomXFlags::default();
        let seed = [0x42u8; 64];
        let mut gen1a = AesGenerator1R::new(seed);
        let mut gen1b = AesGenerator1R::new(seed);
        assert_eq!(gen1a.next(&flags), gen1b.next(&flags));
        assert_eq!(gen1a.next(&flags), gen1b.next(&flags));

        let mut gen4a = AesGenerator4R::new(seed);
        let mut gen4b = AesGenerator4R::new(seed);
        assert_eq!(gen4a.next(&flags), gen4b.next(&flags));
        assert_eq!(gen4a.next(&flags), gen4b.next(&flags));
    }

    #[test]
    fn aes_hash_is_deterministic() {
        let flags = RandomXFlags::default();
        let mut hasher1 = AesHash1R::new();
        let mut hasher2 = AesHash1R::new();
        let mut block = [0u8; 64];
        for (i, byte) in block.iter_mut().enumerate() {
            *byte = i as u8;
        }
        hasher1.update(&block, &flags);
        hasher2.update(&block, &flags);
        assert_eq!(hasher1.finalize(&flags), hasher2.finalize(&flags));
    }

    #[test]
    fn blake_generator_deterministic() {
        let seed = b"seed";
        let mut gen1 = BlakeGenerator::new(seed);
        let mut gen2 = BlakeGenerator::new(seed);
        for _ in 0..32 {
            assert_eq!(gen1.next_u8(), gen2.next_u8());
        }
        assert_eq!(gen1.next_u32(), gen2.next_u32());
    }
}
