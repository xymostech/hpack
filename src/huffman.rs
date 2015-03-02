use std::collections::bit_vec::BitVec;
use std::iter::FromIterator;

#[derive(PartialEq, Debug)]
enum Either<L, R> {
    Left(L),
    Right(R),
}

#[derive(PartialEq, Debug)]
struct HuffmanTree<T>(
    Option<Either<Box<HuffmanTree<T>>, T>>,
    Option<Either<Box<HuffmanTree<T>>, T>>);

impl<T> HuffmanTree<T> {
    pub fn new() -> HuffmanTree<T> {
        HuffmanTree(None, None)
    }

    fn insert_rec(&mut self, code: &BitVec, pos: usize, value: T) {
        if pos == code.len() - 1 {
            // We're at the end, set the value
            if code.get(pos).unwrap() {
                self.0 = Some(Either::Right(value));
            } else {
                self.1 = Some(Either::Right(value));
            }
        } else {
            // If we're not at the end, we propogate the insert in the correct
            // direction, creating a new tree if necessary
            if code.get(pos).unwrap() {
                match self.0 {
                    Some(Either::Left(ref mut tree)) =>
                        // If there's already a tree, just insert
                        tree.insert_rec(code, pos + 1, value),
                    _ => {
                        // Otherwise, make a new one (note, the old value might
                        // not have been `None`, it could have been
                        // `Some(Either::Right(value))`, but we just discard
                        // it).
                        let mut tree = HuffmanTree::new();
                        tree.insert_rec(code, pos + 1, value);
                        self.0 = Some(Either::Left(Box::new(tree)));
                    }
                }
            } else {
                // TODO(emily): de-duplicate this code
                match self.1 {
                    Some(Either::Left(ref mut tree)) =>
                        tree.insert_rec(code, pos + 1, value),
                    _ => {
                        let mut tree = HuffmanTree::new();
                        tree.insert_rec(code, pos + 1, value);
                        self.1 = Some(Either::Left(Box::new(tree)));
                    }
                }
            }
        }
    }

    pub fn insert(&mut self, code: &BitVec, value: T) {
        self.insert_rec(code, 0, value);
    }

    fn lookup_rec(&self, code: &BitVec, pos: usize, size: usize)
            -> Option<(&T, usize)> {
        if pos >= code.len() {
            return None;
        }

        let branch = if code.get(pos).unwrap() {
            &self.0
        } else {
            &self.1
        };

        match branch {
            &Some(Either::Right(ref value)) => Some((value, size)),
            &Some(Either::Left(ref tree)) =>
                tree.lookup_rec(code, pos + 1, size + 1),
            &None => None
        }
    }

    pub fn lookup(&self, code: &BitVec, pos: usize) -> Option<(&T, usize)> {
        self.lookup_rec(code, pos, 1)
    }
}

pub struct HuffmanCode {
    tree: HuffmanTree<u8>,
    mapping: Vec<BitVec>,
}

impl HuffmanCode {
    pub fn new() -> HuffmanCode {
        let map: Vec<BitVec> = FromIterator::from_iter(
            HUFFMAN_CODE.iter().map(|&(val, size)| {
                let mut vec = BitVec::from_bytes(&val);
                vec.truncate(size);
                vec
            }));

        let mut root = HuffmanTree::new();

        for (i, bv) in map.iter().enumerate() {
            // TODO(emily): How do you handle the EOS character?
            if i < 256 {
                root.insert(bv, i as u8);
            }
        }

        HuffmanCode {
            tree: root,
            mapping: map,
        }
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let bitvec = BitVec::from_bytes(data);

        let mut decoded = Vec::new();

        let mut pos = 0;
        loop {
            let result = self.tree.lookup(&bitvec, pos);

            match result {
                Some((val, size)) => {
                    decoded.push(*val);
                    pos += size;
                },
                None => break
            }
        }

        // Ensure that everything was encoded, and all that's left is 1s that
        // make up the EOS.
        if bitvec.len() - pos > 30 {
            return Err(format!("Invalid character at position: {}", pos));
        }

        // Ensure that the remaining bits are all 1s
        for i in pos..bitvec.len() {
            if !bitvec[i] {
                return Err(format!("Invalid ending"));
            }
        }

        Ok(decoded)
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = BitVec::new();

        for val in data {
            let bv = &self.mapping[*val as usize];

            for bit in bv.iter() {
                encoded.push(bit);
            }
        }

        while encoded.len() % 8 != 0 {
            encoded.push(true);
        }

        encoded.to_bytes()
    }
}

#[test]
fn ensure_code_initialization_works() {
    let code = HuffmanCode::new();

    let test_val = [
        true, true, true, true, true, true, true, true,
        true, true, false, false, false];

    assert!(code.mapping[0].eq_vec(&test_val));

    let test_bvec = BitVec::from_bytes(&[0b11111111, 0b11000000]);

    assert_eq!(code.tree.lookup(&test_bvec, 0), Some((&0, 13)));
}

#[test]
fn test_tree_insertion() {
    let mut root: HuffmanTree<u8> = HuffmanTree::new();

    let a = FromIterator::from_iter(vec![true].into_iter());
    let b = FromIterator::from_iter(vec![false, true].into_iter());
    let c = FromIterator::from_iter(vec![false, false].into_iter());

    root.insert(&a, 0);

    assert_eq!(root, HuffmanTree(Some(Either::Right(0)), None));

    root.insert(&b, 1);

    assert_eq!(
        root,
        HuffmanTree(
            Some(Either::Right(0)),
            Some(Either::Left(Box::new(HuffmanTree(
                Some(Either::Right(1)),
                None
            ))))
        )
    );

    root.insert(&c, 2);

    assert_eq!(
        root,
        HuffmanTree(
            Some(Either::Right(0)),
            Some(Either::Left(Box::new(HuffmanTree(
                Some(Either::Right(1)),
                Some(Either::Right(2)),
            ))))
        )
    );
}

#[test]
fn test_tree_lookup() {
    let mut root: HuffmanTree<u8> = HuffmanTree::new();

    let a = FromIterator::from_iter(vec![true].into_iter());
    let b = FromIterator::from_iter(vec![false, true].into_iter());
    let c = FromIterator::from_iter(vec![false, false].into_iter());
    let d = FromIterator::from_iter(vec![true, false].into_iter());
    let e = FromIterator::from_iter(vec![false].into_iter());

    root.insert(&a, 0);
    root.insert(&b, 1);

    assert_eq!(root.lookup(&a, 0), Some((&0, 1)));
    assert_eq!(root.lookup(&b, 0), Some((&1, 2)));
    assert_eq!(root.lookup(&c, 0), None);
    assert_eq!(root.lookup(&d, 0), Some((&0, 1)));
    assert_eq!(root.lookup(&e, 0), None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_decoding_works() {
        let message = &[0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
                        0xab, 0x90, 0xf4, 0xff];

        let code = HuffmanCode::new();

        let decoded = code.decode(message);

        assert_eq!(
            decoded,
            Ok(vec![119, 119, 119, 46, 101, 120, 97, 109,
                    112, 108, 101, 46, 99, 111, 109])
        );
    }

    #[test]
    fn ensure_encoding_works() {
        let message = vec![119, 119, 119, 46, 101, 120, 97, 109,
                          112, 108, 101, 46, 99, 111, 109];

        let code = HuffmanCode::new();

        let encoded = code.encode(&message);

        assert_eq!(
            encoded,
            vec![0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
                 0xab, 0x90, 0xf4, 0xff]
        );
    }
}

static HUFFMAN_CODE: [([u8; 4], usize); 257] = [
    ([0b11111111, 0b11000000, 0b00000000, 0b00000000], 13),
    ([0b11111111, 0b11111111, 0b10110000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11111110, 0b00100000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b00110000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b01000000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b01010000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b01100000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b01110000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b10000000], 28),
    ([0b11111111, 0b11111111, 0b11101010, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11111111, 0b11110000], 30),
    ([0b11111111, 0b11111111, 0b11111110, 0b10010000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b10100000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b11110100], 30),
    ([0b11111111, 0b11111111, 0b11111110, 0b10110000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b11000000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b11010000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b11100000], 28),
    ([0b11111111, 0b11111111, 0b11111110, 0b11110000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b00000000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b00010000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b00100000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b11111000], 30),
    ([0b11111111, 0b11111111, 0b11111111, 0b00110000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b01000000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b01010000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b01100000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b01110000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b10000000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b10010000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b10100000], 28),
    ([0b11111111, 0b11111111, 0b11111111, 0b10110000], 28),
    ([0b01010000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11111110, 0b00000000, 0b00000000, 0b00000000], 10),
    ([0b11111110, 0b01000000, 0b00000000, 0b00000000], 10),
    ([0b11111111, 0b10100000, 0b00000000, 0b00000000], 12),
    ([0b11111111, 0b11001000, 0b00000000, 0b00000000], 13),
    ([0b01010100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11111000, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b11111111, 0b01000000, 0b00000000, 0b00000000], 11),
    ([0b11111110, 0b10000000, 0b00000000, 0b00000000], 10),
    ([0b11111110, 0b11000000, 0b00000000, 0b00000000], 10),
    ([0b11111001, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b11111111, 0b01100000, 0b00000000, 0b00000000], 11),
    ([0b11111010, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b01011000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01011100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01100000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b00000000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b00001000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b00010000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b01100100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01101000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01101100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01110000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01110100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01111000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01111100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10111000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11111011, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b11111111, 0b11111000, 0b00000000, 0b00000000], 15),
    ([0b10000000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11111111, 0b10110000, 0b00000000, 0b00000000], 12),
    ([0b11111111, 0b00000000, 0b00000000, 0b00000000], 10),
    ([0b11111111, 0b11010000, 0b00000000, 0b00000000], 13),
    ([0b10000100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10111010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b10111100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b10111110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11000000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11000010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11000100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11000110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11001000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11001010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11001100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11001110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11010000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11010010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11010100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11010110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11011000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11011010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11011100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11011110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11100000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11100010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11100100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11111100, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b11100110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11111101, 0b00000000, 0b00000000, 0b00000000], 8),
    ([0b11111111, 0b11011000, 0b00000000, 0b00000000], 13),
    ([0b11111111, 0b11111110, 0b00000000, 0b00000000], 19),
    ([0b11111111, 0b11100000, 0b00000000, 0b00000000], 13),
    ([0b11111111, 0b11110000, 0b00000000, 0b00000000], 14),
    ([0b10001000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11111111, 0b11111010, 0b00000000, 0b00000000], 15),
    ([0b00011000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b10001100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b00100000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b10010000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b00101000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b10010100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10011000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10011100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b00110000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b11101000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11101010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b10100000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10100100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b10101000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b00111000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b10101100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11101100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b10110000, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b01000000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b01001000, 0b00000000, 0b00000000, 0b00000000], 5),
    ([0b10110100, 0b00000000, 0b00000000, 0b00000000], 6),
    ([0b11101110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11110000, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11110010, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11110100, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11110110, 0b00000000, 0b00000000, 0b00000000], 7),
    ([0b11111111, 0b11111100, 0b00000000, 0b00000000], 15),
    ([0b11111111, 0b10000000, 0b00000000, 0b00000000], 11),
    ([0b11111111, 0b11110100, 0b00000000, 0b00000000], 14),
    ([0b11111111, 0b11101000, 0b00000000, 0b00000000], 13),
    ([0b11111111, 0b11111111, 0b11111111, 0b11000000], 28),
    ([0b11111111, 0b11111110, 0b01100000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b01001000, 0b00000000], 22),
    ([0b11111111, 0b11111110, 0b01110000, 0b00000000], 20),
    ([0b11111111, 0b11111110, 0b10000000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b01001100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b01010000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b01010100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10110010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b01011000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10110100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10110110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10111000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10111010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10111100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11101011, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b10111110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11101100, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11101101, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b01011100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11000000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11101110, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11000010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11000100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11000110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11001000, 0b00000000], 23),
    ([0b11111111, 0b11111110, 0b11100000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b01100000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11001010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b01100100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11001100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11001110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11101111, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b01101000, 0b00000000], 22),
    ([0b11111111, 0b11111110, 0b11101000, 0b00000000], 21),
    ([0b11111111, 0b11111110, 0b10010000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b01101100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b01110000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11010000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11010010, 0b00000000], 23),
    ([0b11111111, 0b11111110, 0b11110000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b11010100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b01110100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b01111000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11110000, 0b00000000], 24),
    ([0b11111111, 0b11111110, 0b11111000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b01111100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11010110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11011000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b00000000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b00001000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b10000000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b00010000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b11011010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10000100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11011100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11011110, 0b00000000], 23),
    ([0b11111111, 0b11111110, 0b10100000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b10001000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10001100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10010000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11100000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10010100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10011000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11100010, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11111000, 0b00000000], 26),
    ([0b11111111, 0b11111111, 0b11111000, 0b01000000], 26),
    ([0b11111111, 0b11111110, 0b10110000, 0b00000000], 20),
    ([0b11111111, 0b11111110, 0b00100000, 0b00000000], 19),
    ([0b11111111, 0b11111111, 0b10011100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11100100, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10100000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11110110, 0b00000000], 25),
    ([0b11111111, 0b11111111, 0b11111000, 0b10000000], 26),
    ([0b11111111, 0b11111111, 0b11111000, 0b11000000], 26),
    ([0b11111111, 0b11111111, 0b11111001, 0b00000000], 26),
    ([0b11111111, 0b11111111, 0b11111011, 0b11000000], 27),
    ([0b11111111, 0b11111111, 0b11111011, 0b11100000], 27),
    ([0b11111111, 0b11111111, 0b11111001, 0b01000000], 26),
    ([0b11111111, 0b11111111, 0b11110001, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11110110, 0b10000000], 25),
    ([0b11111111, 0b11111110, 0b01000000, 0b00000000], 19),
    ([0b11111111, 0b11111111, 0b00011000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b11111001, 0b10000000], 26),
    ([0b11111111, 0b11111111, 0b11111100, 0b00000000], 27),
    ([0b11111111, 0b11111111, 0b11111100, 0b00100000], 27),
    ([0b11111111, 0b11111111, 0b11111001, 0b11000000], 26),
    ([0b11111111, 0b11111111, 0b11111100, 0b01000000], 27),
    ([0b11111111, 0b11111111, 0b11110010, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b00100000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b00101000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b11111010, 0b00000000], 26),
    ([0b11111111, 0b11111111, 0b11111010, 0b01000000], 26),
    ([0b11111111, 0b11111111, 0b11111111, 0b11010000], 28),
    ([0b11111111, 0b11111111, 0b11111100, 0b01100000], 27),
    ([0b11111111, 0b11111111, 0b11111100, 0b10000000], 27),
    ([0b11111111, 0b11111111, 0b11111100, 0b10100000], 27),
    ([0b11111111, 0b11111110, 0b11000000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b11110011, 0b00000000], 24),
    ([0b11111111, 0b11111110, 0b11010000, 0b00000000], 20),
    ([0b11111111, 0b11111111, 0b00110000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b10100100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b00111000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b01000000, 0b00000000], 21),
    ([0b11111111, 0b11111111, 0b11100110, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b10101000, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b10101100, 0b00000000], 22),
    ([0b11111111, 0b11111111, 0b11110111, 0b00000000], 25),
    ([0b11111111, 0b11111111, 0b11110111, 0b10000000], 25),
    ([0b11111111, 0b11111111, 0b11110100, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11110101, 0b00000000], 24),
    ([0b11111111, 0b11111111, 0b11111010, 0b10000000], 26),
    ([0b11111111, 0b11111111, 0b11101000, 0b00000000], 23),
    ([0b11111111, 0b11111111, 0b11111010, 0b11000000], 26),
    ([0b11111111, 0b11111111, 0b11111100, 0b11000000], 27),
    ([0b11111111, 0b11111111, 0b11111011, 0b00000000], 26),
    ([0b11111111, 0b11111111, 0b11111011, 0b01000000], 26),
    ([0b11111111, 0b11111111, 0b11111100, 0b11100000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b00000000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b00100000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b01000000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b01100000], 27),
    ([0b11111111, 0b11111111, 0b11111111, 0b11100000], 28),
    ([0b11111111, 0b11111111, 0b11111101, 0b10000000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b10100000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b11000000], 27),
    ([0b11111111, 0b11111111, 0b11111101, 0b11100000], 27),
    ([0b11111111, 0b11111111, 0b11111110, 0b00000000], 27),
    ([0b11111111, 0b11111111, 0b11111011, 0b10000000], 26),
    ([0b11111111, 0b11111111, 0b11111111, 0b11111100], 30),
];