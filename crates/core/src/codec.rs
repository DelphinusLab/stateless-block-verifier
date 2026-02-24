use crate::BlockWitness;
use crate::witness::GenesisAccountWitness;
use sbv_primitives::{
    AccessList, Address, B64, B256, BlockNumber, Bloom, Bytes, ChainId, Signature, TxKind, U256,
    types::{
        Header,
        consensus::{Signed, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxEnvelope, TxLegacy},
        eips::eip2930::AccessListItem,
        eips::eip4895::Withdrawal,
        eips::eip4895::Withdrawals,
        eips::eip7702::{Authorization, SignedAuthorization},
    },
};

/// Low-level zero-copy binary codec trait.
///
/// This trait defines raw byte encoding and decoding for types that
/// can be safely serialized via direct memory access.
///
/// # Safety
///
/// Implementations must guarantee that:
/// - `from_raw_bytes` correctly validates input length and alignment.
/// - The memory layout of the type is stable.
/// - No internal pointers are dereferenced after decoding.
///
/// This trait is designed for:
/// - zkVM witness encoding
/// - WASM efficient serialization
/// - zero-copy decoding
pub trait RawCodec {
    /// The decoded output type.
    ///
    /// Usually `Self`, but may differ for wrapper or reference-based types.
    type Output;

    /// Whether this type contains no internal pointers.
    ///
    /// If `true`, the type can be safely copied directly from raw memory.
    /// Defaults to `false`.
    const NO_PTR: bool = false;

    /// Decode a value from raw bytes.
    ///
    /// Returns the decoded value and remaining input slice on success.
    ///
    /// # Safety
    ///
    /// Implementations must ensure that:
    /// - The input is properly validated before reading.
    /// - No uninitialized memory is accessed.
    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])>;

    /// Encode this value into raw bytes.
    ///
    /// Implementations should append the encoded bytes to `dst`.
    fn to_raw_bytes(&self, dst: &mut Vec<u8>);

    /// Returns the encoded byte size of this value.
    fn raw_bytes_size(&self) -> usize;
}

/// Marker trait for types that can be safely encoded using raw memory copying.
pub trait AutoRawCodec {}

macro_rules! impl_auto_raw_codec {
    (
       $ty:ty, $size:expr, $align:expr
   ) => {
        impl AutoRawCodec for $ty {}
        #[cfg(any(target_arch = "x86_64", target_arch = "wasm32"))]
        static_assertions::assert_eq_size!($ty, [u8; $size]);
        #[cfg(any(target_arch = "x86_64", target_arch = "wasm32"))]
        const _: () = assert!(std::mem::align_of::<$ty>() == $align);
    };
}

impl AutoRawCodec for bool {}
impl AutoRawCodec for u8 {}
impl AutoRawCodec for u16 {}
impl AutoRawCodec for u32 {}
impl AutoRawCodec for u64 {}
impl AutoRawCodec for i64 {}
impl AutoRawCodec for i128 {}
impl AutoRawCodec for u128 {}

impl_auto_raw_codec!(B64, 8, 1);
impl_auto_raw_codec!(B256, 32, 1);
impl_auto_raw_codec!(U256, 32, 8);
impl_auto_raw_codec!(Address, 20, 1);
impl_auto_raw_codec!(Bloom, 256, 1);

impl<T> RawCodec for T
where
    T: AutoRawCodec,
{
    type Output = T;
    const NO_PTR: bool = true;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        if data.len() < size_of::<T>() {
            return None;
        }
        let ret;
        unsafe {
            ret = data.as_ptr().cast::<T>().read();
        }
        Some((ret, &data[size_of::<T>()..]))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        unsafe {
            let value_ptr = self as *const Self;
            let bytes_ptr = value_ptr as *const u8;
            let bytes = std::slice::from_raw_parts(bytes_ptr, size_of::<Self>());
            dst.extend_from_slice(bytes);
        }
    }

    fn raw_bytes_size(&self) -> usize {
        size_of::<Self>()
    }
}

impl<T> RawCodec for Vec<T>
where
    T: RawCodec<Output = T>,
{
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (len, mut data) = u32::from_raw_bytes(data)?;
        if !T::NO_PTR {
            let mut values: Vec<T> = Vec::with_capacity(len as usize);
            for _ in 0..len {
                let (value, rem) = T::from_raw_bytes(data)?;
                values.push(value);
                data = rem;
            }

            Some((values, data))
        } else {
            let expect_len = size_of::<T>() * len as usize;
            if data.len() < expect_len {
                return None;
            }

            let mut values: Vec<T> = Vec::with_capacity(len as usize);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    values.as_mut_ptr() as *mut u8,
                    expect_len,
                );
                values.set_len(len as usize);
            }

            Some((values, &data[expect_len..]))
        }
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        (self.len() as u32).to_raw_bytes(dst);

        for value in self {
            value.to_raw_bytes(dst);
        }
    }

    fn raw_bytes_size(&self) -> usize {
        let mut size = 0;
        size += (self.len() as u32).raw_bytes_size();
        for value in self {
            size += value.raw_bytes_size();
        }

        size
    }
}

impl RawCodec for Bytes {
    type Output = Bytes;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (len, data) = u32::from_raw_bytes(data)?;
        let len = len as usize;

        if data.len() < len {
            return None;
        }

        let bytes = bytes::Bytes::copy_from_slice(&data[..len]);

        Some((Bytes(bytes), &data[len..]))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        let len = self.0.len() as u32;
        len.to_raw_bytes(dst);
        dst.extend_from_slice(&self.0);
    }

    fn raw_bytes_size(&self) -> usize {
        4 + self.0.len()
    }
}

impl RawCodec for Withdrawals {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (withdraw, data) = Vec::<Withdrawal>::from_raw_bytes(data)?;

        Some((Self(withdraw), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.0.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        let mut size = 0;
        size += self.0.raw_bytes_size();

        size
    }
}

impl RawCodec for Withdrawal {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (index, data) = u64::from_raw_bytes(data)?;
        let (validator_index, data) = u64::from_raw_bytes(data)?;
        let (address, data) = Address::from_raw_bytes(data)?;
        let (amount, data) = u64::from_raw_bytes(data)?;

        Some((
            Self {
                index,
                validator_index,
                address,
                amount,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.index.to_raw_bytes(dst);
        self.validator_index.to_raw_bytes(dst);
        self.address.to_raw_bytes(dst);
        self.amount.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        let mut size = 0;
        size += self.index.raw_bytes_size();
        size += self.validator_index.raw_bytes_size();
        size += self.address.raw_bytes_size();
        size += self.amount.raw_bytes_size();

        size
    }
}

impl<T: RawCodec<Output = T>> RawCodec for Option<T> {
    type Output = Option<T>;

    const NO_PTR: bool = true;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (flag, data) = bool::from_raw_bytes(data)?;
        if flag {
            let (v, data) = T::from_raw_bytes(data)?;
            Some((Some(v), data))
        } else {
            Some((None, data))
        }
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        match self {
            Some(v) => {
                true.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
            None => {
                false.to_raw_bytes(dst);
            }
        }
    }

    fn raw_bytes_size(&self) -> usize {
        1 + match self {
            Some(v) => v.raw_bytes_size(),
            None => 0,
        }
    }
}

impl RawCodec for Signature {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        // if data.len() < 65 {
        //     return None;
        // }

        let (y_parity, data) = bool::from_raw_bytes(data)?;

        let (r, data) = U256::from_raw_bytes(data)?;
        let (s, data) = U256::from_raw_bytes(data)?;

        Some((Signature::new(r, s, y_parity), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.v().to_raw_bytes(dst);
        self.r().to_raw_bytes(dst);
        self.s().to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.v().raw_bytes_size() + self.r().raw_bytes_size() + self.s().raw_bytes_size()
    }
}

impl<T, Sig> RawCodec for Signed<T, Sig>
where
    T: RawCodec<Output = T>,
    Sig: RawCodec<Output = Sig>,
{
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (tx, data) = T::from_raw_bytes(data)?;
        let (signature, data) = Sig::from_raw_bytes(data)?;

        Some((Signed::new_unhashed(tx, signature), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.tx().to_raw_bytes(dst);
        self.signature().to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.tx().raw_bytes_size() + self.signature().raw_bytes_size()
    }
}

impl RawCodec for TxEnvelope
where
    Signed<TxLegacy>: RawCodec,
    Signed<TxEip2930>: RawCodec,
    Signed<TxEip1559>: RawCodec,
    Signed<TxEip4844>: RawCodec,
    Signed<TxEip7702>: RawCodec,
{
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (tag, data) = u8::from_raw_bytes(data)?;
        // todo 2930,4844,7702 have not been tested as no test data
        let (tx, data) = match tag {
            0 => {
                let (v, data) = Signed::<TxLegacy>::from_raw_bytes(data)?;
                (TxEnvelope::Legacy(v), data)
            }
            1 => {
                let (v, data) = Signed::<TxEip2930>::from_raw_bytes(data)?;
                (TxEnvelope::Eip2930(v), data)
            }
            2 => {
                let (v, data) = Signed::<TxEip1559>::from_raw_bytes(data)?;
                (TxEnvelope::Eip1559(v), data)
            }
            3 => {
                let (v, data) = Signed::<TxEip4844>::from_raw_bytes(data)?;
                (TxEnvelope::Eip4844(v), data)
            }
            4 => {
                let (v, data) = Signed::<TxEip7702>::from_raw_bytes(data)?;
                (TxEnvelope::Eip7702(v), data)
            }
            _ => {
                return {
                    println!("wrong tx tag={tag}");
                    None
                };
            }
        };

        Some((tx, data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        match self {
            Self::Legacy(v) => {
                0u8.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
            Self::Eip2930(v) => {
                1u8.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
            Self::Eip1559(v) => {
                2u8.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
            Self::Eip4844(v) => {
                3u8.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
            Self::Eip7702(v) => {
                4u8.to_raw_bytes(dst);
                v.to_raw_bytes(dst);
            }
        }
    }

    fn raw_bytes_size(&self) -> usize {
        1 + match self {
            Self::Legacy(v) => v.raw_bytes_size(),
            Self::Eip2930(v) => v.raw_bytes_size(),
            Self::Eip1559(v) => v.raw_bytes_size(),
            Self::Eip4844(v) => v.raw_bytes_size(),
            Self::Eip7702(v) => v.raw_bytes_size(),
        }
    }
}

impl RawCodec for TxEip4844 {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = ChainId::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (max_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (max_priority_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (to, data) = Address::from_raw_bytes(data)?;
        let (value, data) = U256::from_raw_bytes(data)?;
        let (access_list, data) = AccessList::from_raw_bytes(data)?;
        let (blob_versioned_hashes, data) = Vec::<B256>::from_raw_bytes(data)?;
        let (max_fee_per_blob_gas, data) = u128::from_raw_bytes(data)?;
        let (input, data) = Bytes::from_raw_bytes(data)?;

        Some((
            Self {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to,
                value,
                access_list,
                blob_versioned_hashes,
                max_fee_per_blob_gas,
                input,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.max_fee_per_gas.to_raw_bytes(dst);
        self.max_priority_fee_per_gas.to_raw_bytes(dst);
        self.to.to_raw_bytes(dst);
        self.value.to_raw_bytes(dst);
        self.access_list.to_raw_bytes(dst);
        self.blob_versioned_hashes.to_raw_bytes(dst);
        self.max_fee_per_blob_gas.to_raw_bytes(dst);
        self.input.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.max_fee_per_gas.raw_bytes_size()
            + self.max_priority_fee_per_gas.raw_bytes_size()
            + self.to.raw_bytes_size()
            + self.value.raw_bytes_size()
            + self.access_list.raw_bytes_size()
            + self.blob_versioned_hashes.raw_bytes_size()
            + self.max_fee_per_blob_gas.raw_bytes_size()
            + self.input.raw_bytes_size()
    }
}

impl RawCodec for TxKind {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (tag, data) = u8::from_raw_bytes(data)?;

        match tag {
            0 => Some((TxKind::Create, data)),
            1 => {
                let (addr, data) = Address::from_raw_bytes(data)?;
                Some((TxKind::Call(addr), data))
            }
            _ => None,
        }
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        match self {
            TxKind::Create => {
                0u8.to_raw_bytes(dst);
            }
            TxKind::Call(addr) => {
                1u8.to_raw_bytes(dst);
                addr.to_raw_bytes(dst);
            }
        }
    }

    fn raw_bytes_size(&self) -> usize {
        1 + match self {
            TxKind::Create => 0,
            TxKind::Call(_) => Address::raw_bytes_size(&Address::ZERO), // or size_of::<Address>()
        }
    }
}

impl RawCodec for TxLegacy {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = Option::<ChainId>::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        let (gas_price, data) = u128::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (to, data) = TxKind::from_raw_bytes(data)?;
        let (value, data) = U256::from_raw_bytes(data)?;
        let (input, data) = Bytes::from_raw_bytes(data)?;

        Some((
            TxLegacy {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                input,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
        self.gas_price.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.to.to_raw_bytes(dst);
        self.value.to_raw_bytes(dst);
        self.input.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.gas_price.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.to.raw_bytes_size()
            + self.value.raw_bytes_size()
            + self.input.raw_bytes_size()
    }
}

impl RawCodec for AccessListItem {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (address, data) = Address::from_raw_bytes(data)?;
        let (storage_keys, data) = Vec::<B256>::from_raw_bytes(data)?;

        Some((
            Self {
                address,
                storage_keys,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.address.to_raw_bytes(dst);
        self.storage_keys.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.address.raw_bytes_size() + self.storage_keys.raw_bytes_size()
    }
}

impl RawCodec for AccessList {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (items, data) = Vec::<AccessListItem>::from_raw_bytes(data)?;
        Some((AccessList(items), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.0.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.0.raw_bytes_size()
    }
}

impl RawCodec for TxEip2930 {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = ChainId::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        let (gas_price, data) = u128::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (to, data) = TxKind::from_raw_bytes(data)?;
        let (value, data) = U256::from_raw_bytes(data)?;
        let (access_list, data) = AccessList::from_raw_bytes(data)?;
        let (input, data) = Bytes::from_raw_bytes(data)?;

        Some((
            TxEip2930 {
                chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                access_list,
                input,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
        self.gas_price.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.to.to_raw_bytes(dst);
        self.value.to_raw_bytes(dst);
        self.access_list.to_raw_bytes(dst);
        self.input.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.gas_price.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.to.raw_bytes_size()
            + self.value.raw_bytes_size()
            + self.access_list.raw_bytes_size()
            + self.input.raw_bytes_size()
    }
}

impl RawCodec for TxEip1559 {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = ChainId::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (max_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (max_priority_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (to, data) = TxKind::from_raw_bytes(data)?;
        let (value, data) = U256::from_raw_bytes(data)?;
        let (access_list, data) = AccessList::from_raw_bytes(data)?;
        let (input, data) = Bytes::from_raw_bytes(data)?;

        Some((
            Self {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to,
                value,
                access_list,
                input,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.max_fee_per_gas.to_raw_bytes(dst);
        self.max_priority_fee_per_gas.to_raw_bytes(dst);
        self.to.to_raw_bytes(dst);
        self.value.to_raw_bytes(dst);
        self.access_list.to_raw_bytes(dst);
        self.input.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.max_fee_per_gas.raw_bytes_size()
            + self.max_priority_fee_per_gas.raw_bytes_size()
            + self.to.raw_bytes_size()
            + self.value.raw_bytes_size()
            + self.access_list.raw_bytes_size()
            + self.input.raw_bytes_size()
    }
}

impl RawCodec for Authorization {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = U256::from_raw_bytes(data)?;
        let (address, data) = Address::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        Some((
            Self {
                chain_id,
                address,
                nonce,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.address.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size() + self.address.raw_bytes_size() + self.nonce.raw_bytes_size()
    }
}

impl RawCodec for SignedAuthorization {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (inner, data) = Authorization::from_raw_bytes(data)?;
        let (y_parity, data) = u8::from_raw_bytes(data)?;
        let (r, data) = U256::from_raw_bytes(data)?;
        let (s, data) = U256::from_raw_bytes(data)?;
        Some((Self::new_unchecked(inner, y_parity, r, s), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.inner().to_raw_bytes(dst);
        self.y_parity().to_raw_bytes(dst);
        self.r().to_raw_bytes(dst);
        self.s().to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.inner().raw_bytes_size()
            + self.y_parity().raw_bytes_size()
            + self.r().raw_bytes_size()
            + self.s().raw_bytes_size()
    }
}

impl RawCodec for TxEip7702 {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = ChainId::from_raw_bytes(data)?;
        let (nonce, data) = u64::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (max_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (max_priority_fee_per_gas, data) = u128::from_raw_bytes(data)?;
        let (to, data) = Address::from_raw_bytes(data)?;
        let (value, data) = U256::from_raw_bytes(data)?;
        let (access_list, data) = AccessList::from_raw_bytes(data)?;
        let (authorization_list, data) = Vec::<SignedAuthorization>::from_raw_bytes(data)?;
        let (input, data) = Bytes::from_raw_bytes(data)?;

        Some((
            Self {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to,
                value,
                access_list,
                authorization_list,
                input,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.max_fee_per_gas.to_raw_bytes(dst);
        self.max_priority_fee_per_gas.to_raw_bytes(dst);
        self.to.to_raw_bytes(dst);
        self.value.to_raw_bytes(dst);
        self.access_list.to_raw_bytes(dst);
        self.authorization_list.to_raw_bytes(dst);
        self.input.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.max_fee_per_gas.raw_bytes_size()
            + self.max_priority_fee_per_gas.raw_bytes_size()
            + self.to.raw_bytes_size()
            + self.value.raw_bytes_size()
            + self.access_list.raw_bytes_size()
            + self.authorization_list.raw_bytes_size()
            + self.input.raw_bytes_size()
    }
}

impl RawCodec for Header {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (parent_hash, data) = B256::from_raw_bytes(data)?;
        let (ommers_hash, data) = B256::from_raw_bytes(data)?;
        let (beneficiary, data) = Address::from_raw_bytes(data)?;
        let (state_root, data) = B256::from_raw_bytes(data)?;
        let (transactions_root, data) = B256::from_raw_bytes(data)?;
        let (receipts_root, data) = B256::from_raw_bytes(data)?;
        let (logs_bloom, data) = Bloom::from_raw_bytes(data)?;
        let (difficulty, data) = U256::from_raw_bytes(data)?;
        let (number, data) = BlockNumber::from_raw_bytes(data)?;
        let (gas_limit, data) = u64::from_raw_bytes(data)?;
        let (gas_used, data) = u64::from_raw_bytes(data)?;
        let (timestamp, data) = u64::from_raw_bytes(data)?;
        let (extra_data, data) = Bytes::from_raw_bytes(data)?;
        let (mix_hash, data) = B256::from_raw_bytes(data)?;
        let (nonce, data) = B64::from_raw_bytes(data)?;

        let (base_fee_per_gas, data) = Option::<u64>::from_raw_bytes(data)?;
        let (withdrawals_root, data) = Option::<B256>::from_raw_bytes(data)?;
        let (blob_gas_used, data) = Option::<u64>::from_raw_bytes(data)?;
        let (excess_blob_gas, data) = Option::<u64>::from_raw_bytes(data)?;
        let (parent_beacon_block_root, data) = Option::<B256>::from_raw_bytes(data)?;
        let (requests_hash, data) = Option::<B256>::from_raw_bytes(data)?;

        Some((
            Header {
                parent_hash,
                ommers_hash,
                beneficiary,
                state_root,
                transactions_root,
                receipts_root,
                logs_bloom,
                difficulty,
                number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                mix_hash,
                nonce,
                base_fee_per_gas,
                withdrawals_root,
                blob_gas_used,
                excess_blob_gas,
                parent_beacon_block_root,
                requests_hash,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.parent_hash.to_raw_bytes(dst);
        self.ommers_hash.to_raw_bytes(dst);
        self.beneficiary.to_raw_bytes(dst);
        self.state_root.to_raw_bytes(dst);
        self.transactions_root.to_raw_bytes(dst);
        self.receipts_root.to_raw_bytes(dst);
        self.logs_bloom.to_raw_bytes(dst);
        self.difficulty.to_raw_bytes(dst);
        self.number.to_raw_bytes(dst);
        self.gas_limit.to_raw_bytes(dst);
        self.gas_used.to_raw_bytes(dst);
        self.timestamp.to_raw_bytes(dst);
        self.extra_data.to_raw_bytes(dst);
        self.mix_hash.to_raw_bytes(dst);
        self.nonce.to_raw_bytes(dst);

        self.base_fee_per_gas.to_raw_bytes(dst);
        self.withdrawals_root.to_raw_bytes(dst);
        self.blob_gas_used.to_raw_bytes(dst);
        self.excess_blob_gas.to_raw_bytes(dst);
        self.parent_beacon_block_root.to_raw_bytes(dst);
        self.requests_hash.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.parent_hash.raw_bytes_size()
            + self.ommers_hash.raw_bytes_size()
            + self.beneficiary.raw_bytes_size()
            + self.state_root.raw_bytes_size()
            + self.transactions_root.raw_bytes_size()
            + self.receipts_root.raw_bytes_size()
            + self.logs_bloom.raw_bytes_size()
            + self.difficulty.raw_bytes_size()
            + self.number.raw_bytes_size()
            + self.gas_limit.raw_bytes_size()
            + self.gas_used.raw_bytes_size()
            + self.timestamp.raw_bytes_size()
            + self.extra_data.raw_bytes_size()
            + self.mix_hash.raw_bytes_size()
            + self.nonce.raw_bytes_size()
            + self.base_fee_per_gas.raw_bytes_size()
            + self.withdrawals_root.raw_bytes_size()
            + self.blob_gas_used.raw_bytes_size()
            + self.excess_blob_gas.raw_bytes_size()
            + self.parent_beacon_block_root.raw_bytes_size()
            + self.requests_hash.raw_bytes_size()
    }
}

impl RawCodec for BlockWitness {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (chain_id, data) = ChainId::from_raw_bytes(data)?;
        let (header, data) = Header::from_raw_bytes(data)?;
        let (prev_state_root, data) = B256::from_raw_bytes(data)?;
        let (transactions, data) = Vec::<TxEnvelope>::from_raw_bytes(data)?;
        let (withdrawals, data) = Option::<Withdrawals>::from_raw_bytes(data)?;
        let (block_hashes, data) = Vec::<B256>::from_raw_bytes(data)?;
        let (states, data) = Vec::<Bytes>::from_raw_bytes(data)?;
        let (codes, data) = Vec::<Bytes>::from_raw_bytes(data)?;

        Some((
            BlockWitness {
                chain_id,
                header,
                prev_state_root,
                transactions,
                withdrawals,
                block_hashes,
                states,
                codes,
            },
            data,
        ))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.chain_id.to_raw_bytes(dst);
        self.header.to_raw_bytes(dst);
        self.prev_state_root.to_raw_bytes(dst);
        self.transactions.to_raw_bytes(dst);
        self.withdrawals.to_raw_bytes(dst);
        self.block_hashes.to_raw_bytes(dst);
        self.states.to_raw_bytes(dst);
        self.codes.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.chain_id.raw_bytes_size()
            + self.header.raw_bytes_size()
            + self.prev_state_root.raw_bytes_size()
            + self.transactions.raw_bytes_size()
            + self.withdrawals.raw_bytes_size()
            + self.block_hashes.raw_bytes_size()
            + self.states.raw_bytes_size()
            + self.codes.raw_bytes_size()
    }
}

impl RawCodec for (Address, u128) {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (addr, data) = Address::from_raw_bytes(data)?;
        let (balance, data) = u128::from_raw_bytes(data)?;

        Some(((addr, balance), data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.0.to_raw_bytes(dst);
        self.1.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.0.raw_bytes_size() + self.1.raw_bytes_size()
    }
}

impl RawCodec for GenesisAccountWitness {
    type Output = Self;

    fn from_raw_bytes(data: &[u8]) -> Option<(Self::Output, &[u8])> {
        let (accounts, data) = Vec::<(Address, u128)>::from_raw_bytes(data)?;

        Some((GenesisAccountWitness { accounts }, data))
    }

    fn to_raw_bytes(&self, dst: &mut Vec<u8>) {
        self.accounts.to_raw_bytes(dst);
    }

    fn raw_bytes_size(&self) -> usize {
        self.accounts.raw_bytes_size()
    }
}

#[cfg(test)]
mod tests {
    use super::BlockWitness;
    use super::*;
    use sbv_primitives::alloy_primitives::bytes;
    use sbv_primitives::{address, b256};

    #[test]
    fn test_input_bytes() {
        let witness = BlockWitness::get_test_data();
        let mut data = Vec::with_capacity(1024 * 300);
        witness.to_raw_bytes(&mut data);

        let mut data_64 = Vec::with_capacity(data.len() / 8);
        crate::utils::put_bytes_to_u64_slice(&data, |x: u64| data_64.push(x));

        let mut data_from_u64 = Vec::with_capacity(1024 * 300);
        let mut idx = 0usize;
        data_from_u64 = crate::utils::get_bytes_from_u64_slice(
            || {
                let v = data_64[idx];
                idx += 1;
                v
            },
            Some(data_from_u64),
        );
        assert_eq!(data, data_from_u64);
    }

    #[test]
    fn test_codec() {
        use crate::BlockWitness;
        let mut data = Vec::new();
        let a: u64 = 10;
        a.to_raw_bytes(&mut data);

        let (b, _) = u64::from_raw_bytes(data.as_slice()).unwrap();
        assert_eq!(a, b);

        let a = BlockWitness::get_test_data();
        a.to_raw_bytes(&mut data);
        println!("data.len={}", data.len());
        let (b, res) = BlockWitness::from_raw_bytes(&data).unwrap();

        assert_eq!(a, b);
        assert_eq!(res.len(), 0);
    }

    #[test]
    fn test_data_fs() {
        let witness = BlockWitness::get_test_data();
        let mut data = Vec::with_capacity(1024 * 500);
        witness.to_raw_bytes(&mut data);
        let bytes = crate::utils::get_bytes_with_length_prefix(&data);

        use std::io::Write;
        let fs = "output.dat";
        let mut file = std::fs::File::create(fs).unwrap();
        file.write_all(&bytes).unwrap();
    }
    #[test]
    fn test_tx() {
        let tx = TxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559 {
                chain_id: 1,
                nonce: 2195,
                gas_limit: 204101,
                max_fee_per_gas: 5136347964,
                max_priority_fee_per_gas: 5000000000,
                to: TxKind::Call(address!("0xef4fb24ad0916217251f553c0596f8edc630eb66")),
                value: U256::from_str_radix("7000000000000000", 10).unwrap(),
                access_list: AccessList(vec![]),
                input: bytes!(
                    "0xb930370100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000199eb29789400000000000000000000000000000000000000000000000000000000000003600000000000000000000000000000000000000000000000000000000000006c83000000000000000000000000000000000000000000000000000000000000038000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001550f7dca700000000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000004585aa71ec2936000000000000000000000000000000000000000000000000000000000000003800000000000000000000000000000000000000000000000000000000000001a00000000000000000000000001d13e6584b37ade465574d96f59d72b5ec021e1a00000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000141d13e6584b37ade465574d96f59d72b5ec021e1a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000141d13e6584b37ade465574d96f59d72b5ec021e1a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014555ce236c0220695b68341bc48c68d52210cc35b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042010100000037c5b3bbf0ba00000000000000000000000000003629ec71aa854500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                ),
            },
            Signature::new(
                U256::from_str_radix(
                    "13699805737577046526522883847620884657343680771556472282301969656600484753265",
                    10,
                )
                .unwrap(),
                U256::from_str_radix(
                    "15010202286730941573396868475476122030908784638356515099309112465270230738778",
                    10,
                )
                .unwrap(),
                false,
            ),
        ));

        let mut data = vec![];
        tx.to_raw_bytes(&mut data);
        let (v, res) = TxEnvelope::from_raw_bytes(&mut data).unwrap();
        assert_eq!(tx, v);
        assert_eq!(res.len(), 0);
    }
}
