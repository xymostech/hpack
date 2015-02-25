use std::result::Result;

use header_table::HeaderTable;

pub struct HPack {
    static_header_table: HeaderTable,
    dynamic_header_table: HeaderTable,
}

impl HPack {
    pub fn new() -> HPack {
        HPack {
            static_header_table: HeaderTable::new_static_table(),
            dynamic_header_table: HeaderTable::new(0),
        }
    }

    pub fn encode_headers(&self, headers: &Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        vec![]
    }

    pub fn decode_headers(&mut self, data: &Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        Ok(vec![])
    }
}
