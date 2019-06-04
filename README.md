[![Latest Version](https://img.shields.io/badge/crates.io-v0.1.1-green.svg)](https://crates.io/crates/rcmerkle)
[![Latest Version](https://img.shields.io/badge/docs.rs-v0.1.1-blue.svg)](https://docs.rs/crate/rcmerkle)

# rcmerkle
*Merkle Tree to calculate Root.*

**Support Two Way:**

- One is traditional use MerkleTree, it need send all hashed list.
- Two is efficient, but need to save state, like state machine. it need send new value, it will return the lastest root. Example: when you have 2^64 (18446744073709551616) data, if you want calculate it's root, you may have memory overflow. but when you use this, your state machine only need store **63** data, and only use **64** time calculate, you will get the lastest merkle root.

### Example:
```rust
use rcmerkle::{BetterMerkleTreeSHA256, Hash, MerkleTreeSHA256, SHA256};

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
```

## License

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

