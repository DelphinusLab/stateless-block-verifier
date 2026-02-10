use crate::codec::RawCodec;

pub fn get_bytes_from_u64_slice<F>(mut input_fn: F, dst: Option<Vec<u8>>) -> Vec<u8>
where
    F: FnMut() -> u64,
{
    let len = input_fn() as usize;

    let mut data = match dst {
        Some(dst) => dst,
        None => Vec::with_capacity(len),
    };
    if data.capacity() < len {
        data.reserve_exact(len - data.capacity());
    }

    for _ in 0..len / size_of::<u64>() {
        let input = input_fn();
        data.extend_from_slice(&input.to_le_bytes());
    }
    let rem = len % size_of::<u64>();
    if rem > 0 {
        let input = input_fn();
        data.extend_from_slice(&input.to_le_bytes()[..rem]);
    }

    data
}

/// head length prefix with bytes
pub fn get_bytes_with_length_prefix(data: &[u8]) -> Vec<u8> {
    let mut out_data = Vec::with_capacity(size_of::<u64>() + data.len());
    let length = data.len() as u64;
    length.to_raw_bytes(&mut out_data);
    out_data.extend_from_slice(&data);
    out_data
}

pub fn put_bytes_to_u64_slice<F>(output_data: &[u8], mut output_fn: F)
where
    F: FnMut(u64),
{
    output_fn(output_data.len() as u64);

    let chunks = output_data.chunks(8);
    for chunk in chunks {
        let mut value = 0u64;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u64) << (i * 8);
        }
        output_fn(value);
    }
}
