use bgpkit_parser::models::{EntryType, MrtRecord};
use bgpkit_parser::mrt_record::parse_common_header;
use bgpkit_parser::BgpkitParser;
use bzip2::bufread::BzDecoder;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use flate2::bufread::GzDecoder;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

mod data_source;

const RECORDS_PER_TYPE: usize = 100;

/// Choose a mix of records with a given MRT type and subtype. The records are chosen to get a
/// uniform distribution of different length records.
fn select_mrt_records<R: Read>(mut input_reader: R, mrt_type: EntryType, subtype: u16) -> Vec<u8> {
    let mut included = Vec::new();
    let mut buffer = Vec::with_capacity(4096);

    while let Ok(header) = parse_common_header(&mut input_reader) {
        buffer.clear();
        header
            .write_header(&mut buffer)
            .expect("able to write header to vec");
        (&mut input_reader)
            .take(header.length as u64)
            .read_to_end(&mut buffer)
            .expect("able to read message body");

        if header.entry_type == mrt_type && header.entry_subtype == subtype {
            included.push(std::mem::replace(&mut buffer, Vec::with_capacity(4096)));
        }
    }

    println!("Found {} included records", included.len());
    included.sort_by_key(Vec::len);

    if included.is_empty() {
        println!("No records found for MRT {:?} {:?}", mrt_type, subtype);
        return Vec::new();
    }

    let mut record_output = Vec::new();
    for n in 0..RECORDS_PER_TYPE {
        let index = (n * included.len()) / RECORDS_PER_TYPE;
        record_output.extend_from_slice(&included[index][..]);
    }

    record_output
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let update_data = data_source::test_data_file("update-example.gz");
    let rib_data = data_source::test_data_file("rib-example-small.bz2");

    let updates_reader = BufReader::new(File::open(update_data).unwrap());
    let mut rib_reader = BufReader::new(File::open(rib_data).unwrap());

    println!("Decompressing input data and loading into memory...");
    let bgp4mp_updates = select_mrt_records(GzDecoder::new(updates_reader), EntryType::BGP4MP, 4);
    let rib_ipv4_unicast =
        select_mrt_records(BzDecoder::new(&mut rib_reader), EntryType::TABLE_DUMP_V2, 2);
    rib_reader.seek(SeekFrom::Start(0)).unwrap();
    let rib_ipv6_unicast =
        select_mrt_records(BzDecoder::new(&mut rib_reader), EntryType::TABLE_DUMP_V2, 4);

    c.bench_function("BGP4MP Update", |b| {
        b.iter_with_large_drop(|| {
            let mut reader = black_box(&bgp4mp_updates[..]);
            let mut holder: [Option<MrtRecord>; RECORDS_PER_TYPE] = std::array::from_fn(|_| None);

            BgpkitParser::from_reader(&mut reader)
                .into_record_iter()
                .enumerate()
                .for_each(|(index, x)| holder[index] = Some(x));

            holder
        })
    });

    c.bench_function("TABLE_DUMP_V2 IPv4 Unicast", |b| {
        b.iter_with_large_drop(|| {
            let mut reader = black_box(&rib_ipv4_unicast[..]);
            let mut holder: [Option<MrtRecord>; RECORDS_PER_TYPE] = std::array::from_fn(|_| None);

            BgpkitParser::from_reader(&mut reader)
                .into_record_iter()
                .enumerate()
                .for_each(|(index, x)| holder[index] = Some(x));

            holder
        })
    });

    c.bench_function("TABLE_DUMP_V2 IPv6 Unicast", |b| {
        b.iter_with_large_drop(|| {
            let mut reader = black_box(&rib_ipv6_unicast[..]);
            let mut holder: [Option<MrtRecord>; RECORDS_PER_TYPE] = std::array::from_fn(|_| None);

            BgpkitParser::from_reader(&mut reader)
                .into_record_iter()
                .enumerate()
                .for_each(|(index, x)| holder[index] = Some(x));

            holder
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark
}
criterion_main!(benches);
