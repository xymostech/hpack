use std::result::Result;

use header_table::HeaderTable;
use huffman::HuffmanCode;

// For tests
use std::num::Int;

pub struct HPack {
    static_header_table: HeaderTable,
    dynamic_header_table: HeaderTable,
    huffman_code: HuffmanCode,
}

fn encode_int_with_prefix(val: usize, prefix_size: usize) -> Vec<u8> {
    let max_in_prefix = 2.pow(prefix_size) - 1;

    if val < 2.pow(prefix_size) - 1 {
        return vec![val as u8];
    }

    let mut encoding = Vec::new();

    encoding.push(max_in_prefix as u8);

    let mut curr_val = val - max_in_prefix;

    while curr_val >= 128 {
        encoding.push((curr_val % 128 + 128) as u8);
        curr_val /= 128;
    }

    encoding.push(curr_val as u8);

    return encoding;
}

fn decode_int_with_prefix(data: &[u8], prefix_size: usize) -> Result<(usize, usize), String> {
    let max_in_prefix: u8 = 2.pow(prefix_size) - 1;

    let mut result: usize = (data[0] & max_in_prefix) as usize;

    if result < max_in_prefix as usize {
        return Ok((result, 1));
    }

    let mut exponent = 0;
    for i in 1..data.len() {
        result += (data[i] & 127) as usize * 2.pow(exponent);
        exponent += 7;
        if data[i] & 128 != 128 {
            return Ok((result, i + 1));
        }
    }

    Err(format!("Reached end of data"))
}

#[test]
fn int_encoding_works() {
    assert_eq!(encode_int_with_prefix(254, 8), vec![254]);
    assert_eq!(encode_int_with_prefix(1, 2), vec![1]);
    assert_eq!(encode_int_with_prefix(300, 8), vec![255, 45]);
    assert_eq!(encode_int_with_prefix(1337, 5), vec![31, 154, 10]);
}

#[test]
fn int_decoding_works() {
    assert_eq!(decode_int_with_prefix(&vec![254], 8), Ok((254, 1)));
    assert_eq!(decode_int_with_prefix(&vec![1], 2), Ok((1, 1)));
    assert_eq!(decode_int_with_prefix(&vec![255, 45], 8), Ok((300, 2)));
    assert_eq!(decode_int_with_prefix(&vec![31, 154, 10], 5), Ok((1337, 3)));

    assert_eq!(decode_int_with_prefix(&vec![255], 8),
               Err(String::from_str("Reached end of data")));
    assert_eq!(decode_int_with_prefix(&vec![255, 128], 8),
               Err(String::from_str("Reached end of data")));
}

#[test]
fn int_representation_is_consistent() {
    // Numbers should be encoded and then decoded back to the same value.
    for i in (1..10000).map(|x| x * 19) {
        for prefix in 1..9 {
            let encoded = encode_int_with_prefix(i, prefix);

            let decoded = decode_int_with_prefix(&encoded, prefix);

            match decoded {
                Ok((val, _)) => {
                    assert_eq!(i, val);
                },
                Err(_) =>
                    panic!("Couldn't decode {:?} (encoded from {})",
                           encoded, i)
            }
        }
    }
}

// For now, we never huffman encode a string
fn encode_string(string: &[u8]) -> Vec<u8> {
    let mut encoded = encode_int_with_prefix(string.len(), 7);

    encoded.push_all(string);

    encoded
}

#[test]
fn string_encoding_works() {
    let test_string = String::from_str("www.example.com").into_bytes();

    assert_eq!(
        encode_string(&test_string),
        vec![0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
             0x65, 0x2e, 0x63, 0x6f, 0x6d]
    );
}

fn decode_string(data: &[u8], huffman_code: &HuffmanCode) ->
        Result<(Vec<u8>, usize), String> {
    let is_huffman_encoded = data[0] & 0x80 == 0x80;
    let (length, bytes_used) = try!(decode_int_with_prefix(data, 7));

    let string_data = &data[bytes_used..(length + bytes_used)];

    if is_huffman_encoded {
        let result = try!(huffman_code.decode(string_data));

        Ok((result, bytes_used + length))
    } else {
        Ok((string_data.to_vec(), bytes_used + length))
    }
}

#[test]
fn string_decoding_works() {
    let no_huffman_data = &[0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61,
                            0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d];

    let huffman_code = HuffmanCode::new();

    let test_string = String::from_str("www.example.com").into_bytes();

    assert_eq!(
        decode_string(no_huffman_data, &huffman_code).unwrap(),
        ((test_string.clone(), 16))
    );

    let huffman_data = &[0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
                         0xab, 0x90, 0xf4, 0xff];

    assert_eq!(
        decode_string(huffman_data, &huffman_code).unwrap(),
        ((test_string.clone(), 13))
    );
}

impl HPack {
    pub fn new(max_table_size: usize) -> HPack {
        HPack {
            static_header_table: HeaderTable::new_static_table(),
            dynamic_header_table: HeaderTable::new(max_table_size),
            huffman_code: HuffmanCode::new(),
        }
    }

    fn lookup_name(&self, name: &Vec<u8>) -> Option<usize> {
        match self.static_header_table.lookup_name(name) {
            Some(index) => Some(index),
            None => {
                match self.dynamic_header_table.lookup_name(name) {
                    Some(index) =>
                        Some(index + self.static_header_table.num_entries()),
                    None => None
                }
            }
        }
    }

    fn lookup_value(&self, value: &(Vec<u8>, Vec<u8>)) -> Option<usize> {
        match self.static_header_table.lookup_value(value) {
            Some(index) => Some(index),
            None => {
                match self.dynamic_header_table.lookup_value(value) {
                    Some(index) =>
                        Some(index + self.static_header_table.num_entries()),
                    None => None
                }
            }
        }
    }

    fn get_at_index(&self, index: usize) -> Result<&(Vec<u8>, Vec<u8>), String> {
        if index <= self.static_header_table.num_entries() {
            Ok(&self.static_header_table[index])
        } else if index - self.static_header_table.num_entries() <=
                self.dynamic_header_table.num_entries() {
            Ok(&self.dynamic_header_table[
                index - self.static_header_table.num_entries()])
        } else {
            Err(format!("Invalid table lookup at index {}", index))
        }
    }

    pub fn encode_headers(&mut self, headers: &[(Vec<u8>, Vec<u8>)]) ->
            Vec<u8> {
        let mut encoded = Vec::new();

        for header in headers {
            let new_data = match self.lookup_value(header) {
                Some(index) => {
                    // Indexed header field
                    // Encode the index
                    let mut encoded_index = encode_int_with_prefix(index, 7);

                    // Set the high bit
                    encoded_index[0] = encoded_index[0] | 0x80;

                    encoded_index
                },
                None => {
                    match self.lookup_name(&header.0) {
                        Some(index) => {
                            // Literal header with indexing, indexed name
                            // First encode the index
                            let mut data =
                                encode_int_with_prefix(index, 6);

                            // Set the next-to-high bit
                            data[0] = data[0] | 0x40;

                            // Add on the encoded string value
                            data.append(
                                &mut encode_string(&header.1));

                            // Store the header
                            self.dynamic_header_table.insert(header.clone());

                            data
                        },
                        None => {
                            // Literal header with indexing, new name
                            // Start with the 0x40 header
                            let mut data = vec![0x40];

                            // Add on the encoded header name
                            data.append(
                                &mut encode_string(&header.0));

                            // Add on the encoded header value
                            data.append(
                                &mut encode_string(&header.1));

                            // Store the header
                            self.dynamic_header_table.insert(header.clone());

                            data
                        }
                    }
                }
            };

            encoded.push_all(&new_data);
        }

        encoded
    }

    pub fn decode_headers(&mut self, data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let mut curr_data = data;

        let mut decoded_headers = Vec::new();

        while curr_data.len() > 0 {
            let first_byte = curr_data[0];

            if first_byte & 0x80 == 0x80 {
                // Indexed representation
                let (index, size) = try!(decode_int_with_prefix(curr_data, 7));

                let value = try!(self.get_at_index(index));

                decoded_headers.push(value.clone());

                curr_data = &curr_data[size..];
            } else if first_byte & 0x20 == 0x20 {
                // Dynamic table size update
                let (max_size, size) = try!(decode_int_with_prefix(curr_data, 5));

                self.dynamic_header_table.new_max_size(max_size);

                curr_data = &curr_data[size..];
            } else {
                // Literal field with incremental indexing or
                // Literal field never indexed or
                // Literal field without indexing
                let index_prefix = if first_byte & 0x40 == 0x40 {
                    6
                } else {
                    4
                };

                let (index, index_size) =
                    try!(decode_int_with_prefix(curr_data, index_prefix));

                curr_data = &curr_data[index_size..];

                let name = if index == 0 {
                    let (name, name_size) =
                        try!(decode_string(curr_data, &self.huffman_code));

                    curr_data = &curr_data[name_size..];

                    name
                } else {
                    let &(ref name, _) = try!(self.get_at_index(index));

                    name.clone()
                };

                let (value, value_size) =
                    try!(decode_string(curr_data, &self.huffman_code));

                if first_byte & 0x40 == 0x40 {
                    self.dynamic_header_table.insert((name.clone(), value.clone()));
                }

                decoded_headers.push((name, value));

                curr_data = &curr_data[value_size..];
            }
        }

        Ok(decoded_headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;

    fn str_to_vec(string: &str) -> Vec<u8> {
        String::from_str(string).into_bytes()
    }

    fn assert_encoding_with_hpack(hpack: &mut HPack,
                                  headers: &Vec<(&str, &str)>,
                                  expected_data: &[u8]) {
        let decoded_headers: Vec<(Vec<u8>, Vec<u8>)> = FromIterator::from_iter(
            headers.iter().map(|&(n, v)| {
                (str_to_vec(n), str_to_vec(v))
            }));

        assert_eq!(
            &hpack.encode_headers(&decoded_headers)[..],
            expected_data
        );
    }

    fn assert_encoding(headers: &Vec<(&str, &str)>, expected_data: &[u8]) {
        let mut hpack = HPack::new(256);
        assert_encoding_with_hpack(&mut hpack, headers, expected_data);
    }

    #[test]
    fn encoding_custom_headers_works() {
        // From C.3.3
        assert_encoding(
            &vec![("custom-key", "custom-value")],
            &[0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
              0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
              0x6c, 0x75, 0x65]);
    }

    #[test]
    fn encoding_stored_header_name_works() {
        // From C.2.2
        assert_encoding(
            &vec![(":path", "/sample/path")],
            &[0x44, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70,
              0x61, 0x74, 0x68]);
    }

    #[test]
    fn encoding_stored_header_value_works() {
        // From C.3.3
        assert_encoding(
            &vec![(":method", "GET")],
            &[0x82]);
    }

    #[test]
    fn encoding_multiple_headers_works() {
        // From C.3.1
        assert_encoding(
            &vec![(":path", "/"),
                  (":authority", "www.example.com")],
            &[0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
              0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d]);
    }

    #[test]
    fn table_values_stored_across_encoding() {
        // From C.3.1
        let mut hpack = HPack::new(256);

        assert_encoding_with_hpack(
            &mut hpack,
            &vec![(":authority", "www.example.com")],
            &[0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
              0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d]);

        assert_encoding_with_hpack(
            &mut hpack,
            &vec![(":authority", "www.example.com")],
            &[0xbe]);
    }

    fn assert_decoding_with_hpack(hpack: &mut HPack, data: &[u8],
                                  expected_headers: &Vec<(&str, &str)>) {
        let decoded_headers = FromIterator::from_iter(
            expected_headers.iter().map(|&(n, v)| {
                (str_to_vec(n), str_to_vec(v))
            }));

        println!("data: {:?}, headers: {:?}", data, expected_headers);

        assert_eq!(
            hpack.decode_headers(data).unwrap(),
            decoded_headers
        );
    }

    fn assert_decoding(data: &[u8], expected_headers: &Vec<(&str, &str)>) {
        let mut hpack = HPack::new(256);
        assert_decoding_with_hpack(&mut hpack, data, expected_headers);
    }

    #[test]
    fn decoding_indexed_works() {
        assert_decoding(&[0x82], &vec![(":method", "GET")]);
    }

    #[test]
    fn decoding_literal_with_indexing_works() {
        // Indexed name, no huffman encoding
        // From C.3.1
        assert_decoding(
            &[0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
              0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d],
            &vec![(":authority", "www.example.com")]);

        // New name, no huffman encoding
        // From C.3.3
        assert_decoding(
            &[0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
              0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
              0x6c, 0x75, 0x65],
            &vec![("custom-key", "custom-value")]);

        // Indexed name, with huffman encoding
        // From C.4.1
        assert_decoding(
            &[0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
              0x90, 0xf4, 0xff],
            &vec![(":authority", "www.example.com")]);

        // New name, with huffman encoding
        // From C.4.3
        assert_decoding(
            &[0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89,
              0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            &vec![("custom-key", "custom-value")]);
    }

    #[test]
    fn decoding_literal_without_indexing_works() {
        // Indexed name, no huffman encoding
        // From C.3.1, changing 0x40 -> 0x00
        assert_decoding(
            &[0x01, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
              0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d],
            &vec![(":authority", "www.example.com")]);

        // New name, no huffman encoding
        // From C.3.3, changing 0x40 -> 0x00
        assert_decoding(
            &[0x00, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
              0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
              0x6c, 0x75, 0x65],
            &vec![("custom-key", "custom-value")]);

        // Indexed name, with huffman encoding
        // From C.4.1, changing 0x40 -> 0x00
        assert_decoding(
            &[0x01, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
              0x90, 0xf4, 0xff],
            &vec![(":authority", "www.example.com")]);

        // New name, with huffman encoding
        // From C.4.3, changing 0x40 -> 0x00
        assert_decoding(
            &[0x00, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89,
              0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            &vec![("custom-key", "custom-value")]);
    }

    #[test]
    fn decoding_literal_never_indexed_works() {
        // Indexed name, no huffman encoding
        // From C.3.1, changing 0x40 -> 0x10
        assert_decoding(
            &[0x11, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
              0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d],
            &vec![(":authority", "www.example.com")]);

        // New name, no huffman encoding
        // From C.3.3, changing 0x40 -> 0x10
        assert_decoding(
            &[0x10, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
              0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61,
              0x6c, 0x75, 0x65],
            &vec![("custom-key", "custom-value")]);

        // Indexed name, with huffman encoding
        // From C.4.1, changing 0x40 -> 0x10
        assert_decoding(
            &[0x11, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
              0x90, 0xf4, 0xff],
            &vec![(":authority", "www.example.com")]);

        // New name, with huffman encoding
        // From C.4.3, changing 0x40 -> 0x10
        assert_decoding(
            &[0x10, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89,
              0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            &vec![("custom-key", "custom-value")]);
    }

    #[test]
    fn decoding_multiple_headers_works() {
        // From C.3.1
        assert_decoding(
            &[0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d,
              0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d],
            &vec![(":path", "/"),
                  (":authority", "www.example.com")]);

        // From C.4.1
        assert_decoding(
            &[0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
              0xab, 0x90, 0xf4, 0xff],
            &vec![(":path", "/"),
                  (":authority", "www.example.com")]);
    }

    #[test]
    fn stored_decoded_headers_persist() {
        // From C.3.1 and C.3.2
        let mut hpack = HPack::new(256);

        assert_decoding_with_hpack(
            &mut hpack,
            &[0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
              0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d],
            &vec![(":authority", "www.example.com")]);

        assert_decoding_with_hpack(
            &mut hpack,
            &[0xbe],
            &vec![(":authority", "www.example.com")]);

        // From C.4.1 and C.4.2
        let mut hpack = HPack::new(256);

        assert_decoding_with_hpack(
            &mut hpack,
            &[0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
              0x90, 0xf4, 0xff],
            &vec![(":authority", "www.example.com")]);

        assert_decoding_with_hpack(
            &mut hpack,
            &[0xbe],
            &vec![(":authority", "www.example.com")]);
    }
}
