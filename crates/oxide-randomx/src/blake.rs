//! Blake2b hashing helpers.

use blake2::digest::VariableOutput;
use blake2::{Blake2b512, Blake2bVar, Digest};

/// Compute a Blake2b-512 hash.
pub fn hash512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    Digest::update(&mut hasher, input);
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out[..]);
    bytes
}

/// Compute a Blake2b-256 hash.
pub fn hash256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid output size");
    blake2::digest::Update::update(&mut hasher, input);
    let mut bytes = [0u8; 32];
    hasher
        .finalize_variable(&mut bytes)
        .expect("output size matches");
    bytes
}

#[cfg(test)]
mod tests {
    use super::{hash256, hash512};

    #[test]
    fn blake2b_known_vectors() {
        assert_eq!(
            hex(&hash512(b"")),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        assert_eq!(
            hex(&hash256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex(&hash512(b"abc")),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        assert_eq!(
            hex(&hash256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        const LUT: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(LUT[(b >> 4) as usize] as char);
            out.push(LUT[(b & 0x0f) as usize] as char);
        }
        out
    }
}
