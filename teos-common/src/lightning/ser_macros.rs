//! A module containing some trait implementation macros to avoid repetition.
//! Most of this file is taken/inspired from [here](https://github.com/lightningdevkit/rust-lightning/blob/3676a056c85f54347e7e079e913317a79e26a2ae/lightning/src/util/ser_macros.rs).

/* This file is licensed under either of
 *  Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
 *  MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
 * at your option.
*/

macro_rules! encode_tlv {
    ($stream: expr, $type: expr, $field: expr, opt) => {
        if let Some(ref field) = $field {
            ser_macros::encode_tlv!($stream, $type, field);
        }
    };
    ($stream: expr, $type: expr, $field: expr, vec) => {
        // Don't write the vector if it's empty.
        if !$field.is_empty() {
            // We can't just pass `$field` since this will move it out of the struct we are implementing
            // this serialization for (but we could have cloned). That's why we pass a reference to it.
            let lightning_vec = ser_utils::LightningVecWriter(&$field);
            ser_macros::encode_tlv!($stream, $type, lightning_vec);
        }
    };
    ($stream: expr, $type: expr, $field: expr, opt_str) => {
        if let Some(ref field) = $field {
            let lightning_str = ser_utils::LightningVecWriter(field.as_bytes());
            ser_macros::encode_tlv!($stream, $type, lightning_str);
        }
    };
    ($stream: expr, $type: expr, $field: expr) => {
        BigSize($type).write($stream)?;
        BigSize($field.serialized_length() as u64).write($stream)?;
        $field.write($stream)?;
    };
}

macro_rules! encode_tlv_stream {
    ($stream: expr, {$(($type: expr, $field: expr, $fieldty: tt)),* $(,)*}) => { {
        #[allow(unused_imports)]
        use {
            lightning::util::ser::BigSize,
            $crate::lightning::{ser_macros, ser_utils},
        };

        $(
            ser_macros::encode_tlv!($stream, $type, $field, $fieldty);
        )*

        #[allow(unused_mut, unused_variables, unused_assignments, unused_comparisons)]
        #[cfg(debug_assertions)]
        {
            let mut last_seen: Option<u64> = None;
            $(
                if let Some(t) = last_seen {
                    debug_assert!(t < $type, "{} <= {}; TLV types must be strictly increasing", $type, t);
                }
                last_seen = Some($type);
            )*
        }
    } }
}

macro_rules! decode_tlv {
    ($reader: expr, $field: ident, opt) => {
        $field = Some(Readable::read(&mut $reader)?);
    };
    ($reader: expr, $field: ident, vec) => {
        let lightning_vec = ser_utils::LightningVecReader::read(&mut $reader)?;
        $field = lightning_vec.0;
    };
    ($reader: expr, $field: ident, opt_str) => {
        let lightning_str = ser_utils::LightningVecReader::read(&mut $reader)?;
        let inner_str =
            String::from_utf8(lightning_str.0).map_err(|_| DecodeError::InvalidValue)?;
        $field = Some(inner_str);
    };
}

macro_rules! decode_tlv_stream {
    ($stream: expr, {$(($type: expr, $field: ident, $fieldty: tt)),* $(,)*}) => { {
        #[allow(unused_imports)]
        use {
            lightning::ln::msgs::DecodeError,
            lightning::util::ser::{BigSize, Readable},
            $crate::lightning::{ser_macros, ser_utils},
        };

        let mut last_seen_type: Option<u64> = None;
        let mut stream_ref = $stream;

        loop {
            // First decode the type of this TLV:
            let typ: BigSize = {
                let mut tracking_reader = ser_utils::ReadTrackingReader::new(&mut stream_ref);
                match Readable::read(&mut tracking_reader) {
                    Err(DecodeError::ShortRead) => {
                        if !tracking_reader.have_read {
                            break;
                        } else {
                            return Err(DecodeError::ShortRead);
                        }
                    },
                    Err(e) => return Err(e),
                    Ok(t) => t,
                }
            };

            // Types must be unique and monotonically increasing:
            match last_seen_type {
                Some(t) if typ.0 <= t => {
                    return Err(DecodeError::InvalidValue);
                },
                _ => {},
            }
            last_seen_type = Some(typ.0);

            // Finally, read the length and value itself:
            let length: BigSize = Readable::read(&mut stream_ref)?;
            let mut s = ser_utils::FixedLengthReader::new(&mut stream_ref, length.0);
            match typ.0 {
                $($type => {
                    ser_macros::decode_tlv!(s, $field, $fieldty);
                    if s.bytes_remain() {
                        s.eat_remaining()?; // Return ShortRead if there's actually not enough bytes
                        return Err(DecodeError::InvalidValue);
                    }
                },)*
                x if x % 2 == 0 => {
                    return Err(DecodeError::UnknownRequiredFeature);
                },
                _ => {},
            }
            s.eat_remaining()?;
        }
    } }
}

macro_rules! init_tlv_field_var {
    ($field: ident, opt) => {
        let mut $field = None;
    };
    ($field: ident, vec) => {
        let mut $field = Vec::new();
    };
    ($field: ident, opt_str) => {
        let mut $field = None;
    };
}

macro_rules! impl_writeable_msg {
    ($st: ty, {$($field: ident),* $(,)*}, {$(($type: expr, $tlvfield: ident, $fieldty: tt)),* $(,)*}) => {
        impl lightning::util::ser::Writeable for $st {
            fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), lightning::io::Error> {
                $(self.$field.write(w)?;)*
                $crate::lightning::ser_macros::encode_tlv_stream!(w, {$(($type, self.$tlvfield, $fieldty)),*});
                Ok(())
            }
        }

        impl lightning::util::ser::Readable for $st {
            fn read<R: lightning::io::Read>(r: &mut R) -> Result<Self, lightning::ln::msgs::DecodeError> {
                $(let $field = lightning::util::ser::Readable::read(r)?;)*
                $($crate::lightning::ser_macros::init_tlv_field_var!($tlvfield, $fieldty);)*
                $crate::lightning::ser_macros::decode_tlv_stream!(r, {$(($type, $tlvfield, $fieldty)),*});
                Ok(Self {
                    $($field),*,
                    $($tlvfield),*
                })
            }
        }

        #[cfg(test)]
        impl std::cmp::PartialEq for $st {
            fn eq(&self, other: &Self) -> bool {
                true
                $(&& self.$field == other.$field)*
                $(&& self.$tlvfield == other.$tlvfield)*
            }
        }
    }
}

macro_rules! set_msg_type {
    ($st: ty, $type: expr) => {
        impl $crate::lightning::ser_utils::Type for $st {
            const TYPE: u16 = $type;
        }
    };
}

// Macros used by `impl_writeable_msg`.
pub(super) use decode_tlv;
pub(super) use decode_tlv_stream;
pub(super) use encode_tlv;
pub(super) use encode_tlv_stream;
pub(super) use init_tlv_field_var;

pub(super) use impl_writeable_msg;
pub(super) use set_msg_type;
