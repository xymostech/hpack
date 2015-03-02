use std::vec::Vec;
use std::ops::Index;
use std::iter::FromIterator;

static INITIAL_STATIC_TABLE: [(&'static str, &'static str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

pub struct HeaderTable {
    table: Vec<(Vec<u8>, Vec<u8>)>,
    max_size: usize,
}

impl HeaderTable {
    pub fn new(start_max_size: usize) -> HeaderTable {
        HeaderTable {
            table: Vec::new(),
            max_size: start_max_size,
        }
    }

    pub fn new_static_table() -> HeaderTable {
        let mut initial_table = Vec::new();

        for entry in INITIAL_STATIC_TABLE.iter() {
            let &(header, value) = entry;

            let header_bytes = FromIterator::from_iter(header.bytes());
            let value_bytes = FromIterator::from_iter(value.bytes());

            initial_table.push((header_bytes, value_bytes));
        }

        HeaderTable {
            table: initial_table,
            max_size: 0
        }
    }

    pub fn num_entries(&self) -> usize {
        self.table.len()
    }

    pub fn insert(&mut self, entry: (Vec<u8>, Vec<u8>)) {
        self.table.insert(0, entry);
        self.truncate_table();
    }

    pub fn lookup_value(&self, compare: &(Vec<u8>, Vec<u8>)) -> Option<usize> {
        for i in 0..self.table.len() {
            let entry = &self.table[i];

            if entry.0 == compare.0 && entry.1 == compare.1 {
                return Some(i + 1);
            }
        }

        return None;
    }

    pub fn lookup_name(&self, compare: &Vec<u8>) -> Option<usize> {
        for i in 0..self.table.len() {
            let entry = &self.table[i];

            if entry.0 == *compare {
                return Some(i + 1);
            }
        }

        return None;
    }

    pub fn new_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.truncate_table();
    }

    fn truncate_table(&mut self) {
        let mut curr_size = 0;

        for i in 0..self.table.len() {
            let entry_size = self.table[i].0.len() + self.table[i].1.len() + 32;

            if curr_size + entry_size > self.max_size {
                self.table.truncate(i);
                return;
            }

            curr_size += entry_size;
        }
    }
}

impl Index<usize> for HeaderTable {
    type Output = (Vec<u8>, Vec<u8>);

    fn index(&self, index: &usize) -> &(Vec<u8>, Vec<u8>) {
        &self.table[*index - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn making_tables_works() {
        let table = HeaderTable::new(0);

        assert_eq!(table.num_entries(), 0);
    }

    #[test]
    fn making_static_tables_works() {
        let static_table = HeaderTable::new_static_table();

        assert_eq!(static_table.num_entries(), 61);
    }

    #[test]
    fn basic_functions_work() {
        let mut table = HeaderTable::new(100);

        assert_eq!(table.num_entries(), 0);

        table.insert((vec![0, 1, 2], vec![3, 4, 5]));

        // There's only one value in the table
        assert_eq!(table.num_entries(), 1);
        assert_eq!(table[1], (vec![0, 1, 2], vec![3, 4, 5]));

        table.insert((vec![6, 7, 8], vec![9, 10, 11]));

        // There's another value in the table, and the indices shifted
        assert_eq!(table.num_entries(), 2);
        assert_eq!(table[1], (vec![6, 7, 8], vec![9, 10, 11]));
        assert_eq!(table[2], (vec![0, 1, 2], vec![3, 4, 5]));
    }

    #[test]
    fn lookup_works() {
        let mut table = HeaderTable::new(100);

        table.insert((vec![0, 1, 2], vec![3, 4, 5]));

        // Unwrap will throw if this isn't in the table
        let value_result =
            table.lookup_value(&(vec![0, 1, 2], vec![3, 4, 5])).unwrap();

        // The value is at the right index
        assert_eq!(value_result, 1);

        // Lookup just the 'name' portion.
        let name_result = table.lookup_name(&vec![0, 1, 2]).unwrap();

        // The name is at the right index
        assert_eq!(name_result, 1);

        // A value not in the table returns none
        assert_eq!(table.lookup_value(&(vec![0], vec![1])), None);
    }

    #[test]
    fn static_table_is_correct() {
        let table = HeaderTable::new_static_table();

        let &(ref header1, ref value1) = &table[2];
        let &(ref header2, ref value2) = &table[61];

        // Some value is in the table
        assert_eq!(str::from_utf8(&header1).unwrap(), ":method");
        assert_eq!(str::from_utf8(&value1).unwrap(), "GET");

        // Some other value is in the table
        assert_eq!(str::from_utf8(&header2).unwrap(), "www-authenticate");
        assert_eq!(str::from_utf8(&value2).unwrap(), "");
    }

    #[test]
    fn ejecting_elements_works() {
        let mut table = HeaderTable::new(40);

        table.insert((vec![0, 1, 2], vec![3, 4, 5]));
        table.insert((vec![6, 7, 8], vec![9, 10, 11]));

        // There's only one value
        assert_eq!(table.num_entries(), 1);

        // The first value is the new one
        assert_eq!(table[1], (vec![6, 7, 8], vec![9, 10, 11]));

        // The old value isn't in the table any more
        assert_eq!(table.lookup_value(&(vec![0, 1, 2], vec![3, 4, 5])), None);
    }

    #[test]
    fn setting_max_size_ejects() {
        let mut table = HeaderTable::new(80);

        table.insert((vec![0, 1, 2], vec![3, 4, 5]));
        table.insert((vec![6, 7, 8], vec![9, 10, 11]));

        // Both values fit at first
        assert_eq!(table.num_entries(), 2);

        table.new_max_size(40);

        // Now, only one value is in the table
        assert_eq!(table.num_entries(), 1);

        // The old value isn't in the table any more
        assert_eq!(table.lookup_value(&(vec![0, 1, 2], vec![3, 4, 5])), None);
    }
}
