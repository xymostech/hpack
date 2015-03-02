### hpack

##### An implementation of the HTTP/2 header compression format

-------

This is a first try at implementing the HPACK format for use in a personal
project involving HTTP/2. It builds off of the current HPACK spec, found at:
http://http2.github.io/http2-spec/compression.html

I haven't written much Rust, so this is also an experiment for me to try it
out.

#### API

```rust
pub struct HPack {
    ...
}
```

```rust
impl HPack {
    pub fn new(max_table_size: usize) -> HPack;
    pub fn encode_headers(&mut self, headers: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8>;
    pub fn decode_headers(&mut self, data: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String>;
}
```

Use `new` to create an `HPack`, and then `encode_headers` and `decode_headers`
to encode and decode headers. Note that headers are implemented as tuples of
`Vec<u8>` instead of `String`. The values can contain arbitrary bytes, so they
aren't compatible with UTF-8. The names probably should be strings, but are
left this way to make things easier. This API will probably change.
