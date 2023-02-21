//! A helper module containing some lightning messages serialization stuff.
//! Most of this file is taken/inspired from [here](https://github.com/lightningdevkit/rust-lightning/blob/3676a056c85f54347e7e079e913317a79e26a2ae/lightning/src/util/ser.rs).

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

use crate::appointment::{Locator, LOCATOR_LEN};
use crate::UserId;

use bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE;
use lightning::io::{copy, sink, Error, ErrorKind, Read};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{MaybeReadable, Readable, Writeable, Writer};

/// A trait that associates a u16 [`Type::TYPE`] constant with a lightning message.
pub trait Type {
    /// The type identifying the message payload.
    const TYPE: u16;
}

// Deserialization for a Locator inside a lightning message.
impl Readable for Locator {
    fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut buf = [0; LOCATOR_LEN];
        reader.read_exact(&mut buf)?;
        Self::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)
    }
}

// Serialization for a Locator inside a lighting message.
impl Writeable for Locator {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(&self.to_vec())
    }
}

// Deserialization for a UserId inside a lightning message.
impl Readable for UserId {
    fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut buf = [0; PUBLIC_KEY_SIZE];
        reader.read_exact(&mut buf)?;
        Self::from_slice(&buf).map_err(|_| DecodeError::InvalidValue)
    }
}

// Serialization for a UserId inside a lighting message.
impl Writeable for UserId {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        self.0.write(writer)
    }
}

/// A read wrapper around a vector inside a lightning message.
/// This wrapper mainly exists because we cannot implement LDK's (de)serialization traits
/// for Vec (since neither the traits nor Vec are defined in our crate (the orphan rule)).
///
/// [`Readable`] implementation for this struct assumes that there is no length prefix.
/// It will read the vector until there are no more items in the stream (Don't use with non-TLV field).
pub(super) struct LightningVecReader<T>(pub Vec<T>);

// Deserialization for a vector of items inside a lightning message.
impl<T: MaybeReadable> Readable for LightningVecReader<T> {
    #[inline]
    fn read<R: Read>(mut reader: &mut R) -> Result<Self, DecodeError> {
        let mut values = Vec::new();
        loop {
            let mut track_read = ReadTrackingReader::new(&mut reader);
            match MaybeReadable::read(&mut track_read) {
                Ok(Some(v)) => {
                    values.push(v);
                }
                Ok(None) => {}
                // If we failed to read any bytes at all, we reached the end of our TLV
                // stream and have simply exhausted all entries.
                Err(ref e) if e == &DecodeError::ShortRead && !track_read.have_read => break,
                Err(e) => return Err(e),
            }
        }
        Ok(Self(values))
    }
}

/// A write wrapper around a vector/slice inside a lightning message.
/// Similar to [`LightningVecReader`] but the inner vector is a slice reference to avoid cloning.
///
/// Note that we don't prefix the vector/slice with its length when serializing it, that's because this struct
/// is used in TLV streams which already has a BigSize length prefix (Don't use with non-TLV field).
pub(super) struct LightningVecWriter<'a, T>(pub &'a [T]);

// Serialization for a vector of items inside a lighting message.
impl<'a, T: Writeable> Writeable for LightningVecWriter<'a, T> {
    #[inline]
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
        for item in self.0.iter() {
            item.write(writer)?;
        }
        Ok(())
    }
}

/// Essentially std::io::Take but a bit simpler and with a method to walk the underlying stream
/// forward to ensure we always consume exactly the fixed length specified.
pub(super) struct FixedLengthReader<R: Read> {
    read: R,
    bytes_read: u64,
    total_bytes: u64,
}

impl<R: Read> FixedLengthReader<R> {
    /// Returns a new FixedLengthReader.
    pub fn new(read: R, total_bytes: u64) -> Self {
        Self {
            read,
            bytes_read: 0,
            total_bytes,
        }
    }

    /// Returns whether there are remaining bytes or not.
    #[inline]
    pub fn bytes_remain(&mut self) -> bool {
        self.bytes_read != self.total_bytes
    }

    /// Consume the remaining bytes.
    #[inline]
    pub fn eat_remaining(&mut self) -> Result<(), DecodeError> {
        copy(self, &mut sink()).or(Err(DecodeError::Io(ErrorKind::Other)))?;
        if self.bytes_read != self.total_bytes {
            Err(DecodeError::ShortRead)
        } else {
            Ok(())
        }
    }
}

impl<R: Read> Read for FixedLengthReader<R> {
    #[inline]
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, Error> {
        if self.total_bytes == self.bytes_read {
            Ok(0)
        } else {
            let read_len = core::cmp::min(dest.len() as u64, self.total_bytes - self.bytes_read);
            match self.read.read(&mut dest[0..(read_len as usize)]) {
                Ok(v) => {
                    self.bytes_read += v as u64;
                    Ok(v)
                }
                Err(e) => Err(e),
            }
        }
    }
}

/// A Read which tracks whether any bytes have been read at all. This allows us to distinguish
/// between "EOF reached before we started" and "EOF reached mid-read".
pub(super) struct ReadTrackingReader<R: Read> {
    read: R,
    /// Tells whether we have read from this reader or not yet.
    pub have_read: bool,
}

impl<R: Read> ReadTrackingReader<R> {
    /// Returns a new ReadTrackingReader.
    pub fn new(read: R) -> Self {
        Self {
            read,
            have_read: false,
        }
    }
}

impl<R: Read> Read for ReadTrackingReader<R> {
    #[inline]
    fn read(&mut self, dest: &mut [u8]) -> Result<usize, Error> {
        match self.read.read(dest) {
            Ok(0) => Ok(0),
            Ok(len) => {
                self.have_read = true;
                Ok(len)
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod test_utils {
    use crate::appointment::{Locator, LOCATOR_LEN};
    use crate::cryptography::get_random_bytes;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    pub use lightning::util::test_utils::TestVecWriter;

    pub fn get_random_locator() -> Locator {
        let bytes = get_random_bytes(LOCATOR_LEN);
        Locator::from_slice(&bytes).unwrap()
    }

    pub fn get_random_txid() -> Txid {
        let bytes = get_random_bytes(32);
        Txid::from_slice(&bytes).unwrap()
    }

    #[allow(dead_code)]
    pub fn get_random_string(size: usize) -> String {
        let bytes = get_random_bytes(size);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[cfg(test)]
pub(super) use test_utils::*;
