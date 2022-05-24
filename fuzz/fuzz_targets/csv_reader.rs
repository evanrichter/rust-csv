#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (
    &[u8],
    Option<u8>,
    bool,
    bool,
    usize,
    Option<u8>,
    u8,
    bool,
    u8,
    bool,
    Option<u8>,
    u8,
)| {
    let terminator =
        data.10.map(|c| csv::Terminator::Any(c)).unwrap_or_default();

    let trim = match data.11 & 0b11 {
        0b00 => csv::Trim::Headers,
        0b01 => csv::Trim::Fields,
        0b10 => csv::Trim::All,
        0b11.. => csv::Trim::None,
    };

    let mut rdr = csv::ReaderBuilder::new()
        .escape(data.1)
        .has_headers(data.2)
        .double_quote(data.3)
        .buffer_capacity(data.4 % 0x10000)
        .comment(data.5)
        .delimiter(data.6)
        .flexible(data.7)
        .quote(data.8)
        .quoting(data.9)
        .terminator(terminator)
        .trim(trim)
        .from_reader(data.0);

    let _: Vec<_> = rdr.byte_records().collect();

    // all string records are valid byte records, so iterate those next
    let _: Vec<_> = rdr.records().collect();
});
