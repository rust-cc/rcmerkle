//! Merkle Tree to calculate Root.
//! Support Two Way:
//! One is traditional use MerkleTree, it need send all hashed list.
//! Two is efficient, but need to save state, like state machine. it
//! need send new value, it will return the lastest root.
//! Example:
//! ```rust
//! use rcmerkle::{BetterMerkleTreeSHA256, Hash, MerkleTreeSHA256, SHA256};
//!
//! let list = [
//!    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
//! ];
//! let hashed_list: Vec<SHA256> = list.iter().map(|v| SHA256::hash(v.as_bytes())).collect();
//! let mut better_merkle = BetterMerkleTreeSHA256::new();
//!
//! for i in 0..hashed_list.len() {
//!    let root1 = MerkleTreeSHA256::root(hashed_list[0..i + 1].to_vec());
//!    let root2 = better_merkle.root(hashed_list[i].clone());
//!    assert_eq!(root1, root2);
//! }
//! ```

use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;

/// trait to define different hash function
pub trait Hash: Default + Clone + Eq + PartialEq {
    fn hash(data: &[u8]) -> Self;

    fn to_string(hash: &Self) -> String;
}

/// Traditional merkle tree.
pub struct MerkleTree<H: Hash>(PhantomData<H>);

/// Efficient, and save state.
pub struct BetterMerkleTree<H: Hash>(Vec<H>, H);

impl<H: Hash> MerkleTree<H> {
    /// Recursive calculation.
    fn merkle(mut vec: Vec<H>) -> Vec<H> {
        let vec_len = vec.len();
        if vec_len == 1 {
            return vec;
        }

        let mut next = vec![];
        let (mut r, m) = (vec_len / 2, vec_len % 2);
        if m == 1 {
            let last = vec[vec_len - 1].clone();
            vec.push(last);
            r += 1;
        }

        for i in 0..r {
            let mut s1 = H::to_string(&vec[i * 2]);
            s1.push_str(&H::to_string(&vec[i * 2 + 1]));
            next.push(H::hash(s1.as_bytes()))
        }

        MerkleTree::merkle(next)
    }

    /// new a MerkleTree, maybe not use.
    pub fn new() -> Self {
        MerkleTree(Default::default())
    }

    /// Entrance, input your list. and return merkle root.
    pub fn root(hashes: Vec<H>) -> H {
        if hashes.len() == 0 {
            return Default::default();
        }

        MerkleTree::merkle(hashes).remove(0)
    }
}

impl<H: Hash> BetterMerkleTree<H> {
    /// Recursive calculation.
    fn merkle(&mut self, new: H, is_full: bool, round: usize) -> H {
        let mut next_full = false;

        if self.0.len() <= round {
            let mut need_append = true;
            for i in self.0.iter() {
                if i != &H::default() {
                    need_append = false;
                }
            }
            if need_append {
                self.0.push(new.clone())
            }

            return new;
        }

        let next = if self.0[round] != H::default() {
            let mut s1 = H::to_string(&self.0[round]);
            s1.push_str(&H::to_string(&new));

            if is_full {
                self.0[round] = H::default();
                next_full = true;
            }

            H::hash(s1.as_bytes())
        } else {
            let mut s1 = H::to_string(&new);
            s1.push_str(&s1.clone());

            if is_full {
                self.0[round] = new;
            }

            H::hash(s1.as_bytes())
        };

        self.merkle(next, next_full, round + 1)
    }

    /// when start, you need new this state machine.
    pub fn new() -> Self {
        BetterMerkleTree(vec![], Default::default())
    }

    /// load the state machine.
    pub fn load(vec: Vec<H>) -> Self {
        BetterMerkleTree(vec, Default::default())
    }

    /// output the state machine status.
    pub fn helper(&self) -> &Vec<H> {
        &self.0
    }

    /// get now root.
    pub fn now(&self) -> &H {
        &self.1
    }

    /// Entrance, when new input to this machine.
    pub fn root(&mut self, new: H) -> H {
        let hash = self.merkle(new, true, 0);
        self.1 = hash.clone();
        hash
    }
}

/// helper SHA256
#[derive(Default, Clone, Eq, PartialEq)]
pub struct SHA256([u8; 32]);

impl Hash for SHA256 {
    fn hash(data: &[u8]) -> Self {
        let mut h: SHA256 = Default::default();
        let mut hasher = Sha256::new();
        hasher.input(data);
        h.0.copy_from_slice(&hasher.result()[..]);
        h
    }

    fn to_string(hash: &Self) -> String {
        format!("{}", hash)
    }
}

impl Display for SHA256 {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut hex = String::new();
        hex.extend(self.0.iter().map(|byte| format!("{:02x?}", byte)));
        write!(f, "0x{}", hex)
    }
}

impl Debug for SHA256 {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut hex = String::new();
        hex.extend(self.0.iter().map(|byte| format!("{:02x?}", byte)));
        write!(f, "0x{}", hex)
    }
}

/// helper Keccak256(SHA3)
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Keccak256([u8; 32]);

impl Hash for Keccak256 {
    fn hash(data: &[u8]) -> Self {
        let mut h: Keccak256 = Default::default();
        let mut hasher = Sha3_256::new();
        hasher.input(data);
        h.0.copy_from_slice(&hasher.result()[..]);
        h
    }

    fn to_string(hash: &Self) -> String {
        format!("{}", hash)
    }
}

impl Display for Keccak256 {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut hex = String::new();
        hex.extend(self.0.iter().map(|byte| format!("{:02x?}", byte)));
        write!(f, "0x{}", hex)
    }
}

impl Debug for Keccak256 {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let mut hex = String::new();
        hex.extend(self.0.iter().map(|byte| format!("{:02x?}", byte)));
        write!(f, "0x{}", hex)
    }
}

pub type MerkleTreeSHA256 = MerkleTree<SHA256>;
pub type BetterMerkleTreeSHA256 = BetterMerkleTree<SHA256>;

pub type MerkleTreeKeccak256 = MerkleTree<Keccak256>;
pub type BetterMerkleTreeKeccak256 = BetterMerkleTree<Keccak256>;

#[cfg(test)]
mod tests {
    use super::{
        BetterMerkleTreeKeccak256, BetterMerkleTreeSHA256, Hash, Keccak256, MerkleTreeKeccak256,
        MerkleTreeSHA256, SHA256,
    };

    #[test]
    fn test_sha256() {
        let list = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
        ];
        let hashed_list: Vec<SHA256> = list.iter().map(|v| SHA256::hash(v.as_bytes())).collect();
        let mut better_merkle = BetterMerkleTreeSHA256::new();

        for i in 0..hashed_list.len() {
            let root1 = MerkleTreeSHA256::root(hashed_list[0..i + 1].to_vec());
            let root2 = better_merkle.root(hashed_list[i].clone());
            assert_eq!(root1, root2);
        }
    }

    #[test]
    fn test_keccak() {
        let list = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
        ];
        let hashed_list: Vec<Keccak256> =
            list.iter().map(|v| Keccak256::hash(v.as_bytes())).collect();
        let mut better_merkle = BetterMerkleTreeKeccak256::new();

        for i in 0..hashed_list.len() {
            let root1 = MerkleTreeKeccak256::root(hashed_list[0..i + 1].to_vec());
            let root2 = better_merkle.root(hashed_list[i].clone());
            assert_eq!(root1, root2);
        }
    }
}
