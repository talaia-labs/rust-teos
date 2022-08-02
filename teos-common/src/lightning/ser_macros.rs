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

#[cfg(test)]
mod tests {
    use crate::appointment::{Locator, LOCATOR_LEN};
    use crate::lightning::ser_utils::Type;
    use crate::lightning::{ser_macros, ser_utils};
    use lightning::io;
    use lightning::ln::msgs::DecodeError;
    use lightning::util::ser::{BigSize, Readable, Writeable};

    macro_rules! encode_decode_tlv {
        ($typ: expr, $field: expr, $fieldty: tt) => {{
            // Encode the TLV to a stream.
            let mut stream = ser_utils::TestVecWriter(Vec::new());
            encode_tlv!(&mut stream, $typ, $field, $fieldty);
            // Get a reader with the writer's buffer.
            let mut cursor = io::Cursor::new(stream.0);
            let mut stream = ser_utils::ReadTrackingReader::new(&mut cursor);
            init_tlv_field_var!(read_field, $fieldty);
            #[allow(unreachable_code)]
            if false {
                unreachable!();
                // This assignment will let the compiler infer the type of `read_field`.
                read_field = $field;
            }
            // Try to read from the stream. Note that the stream might be empty if `$field`
            // carried no info to be written in the first place.
            let read_typ_result = BigSize::read(&mut stream);
            if let Ok(read_typ) = read_typ_result {
                let read_len = BigSize::read(&mut stream)?;
                let mut stream = ser_utils::FixedLengthReader::new(&mut cursor, read_len.0);
                decode_tlv!(stream, read_field, $fieldty);
                Ok((read_typ.0, read_len.0, read_field))
            } else if !stream.have_read {
                Ok(($typ, 0, read_field))
            } else {
                Err(read_typ_result.err().unwrap())
            }
        }};
    }

    macro_rules! test_encode_decode_tlv {
        ($typ: expr, $len: expr, $val: expr, $fieldty: tt) => {
            let (typ, len, val) = encode_decode_tlv!($typ, $val, $fieldty)?;
            assert_eq!($typ as u64, typ, "Invalid TLV type");
            assert_eq!($len as u64, len, "Invalid TLV length");
            assert_eq!($val, val, "Invalid TLV value");
        };
    }

    macro_rules! test_opt_ranged_type {
        ($type: ident, $expected_len: expr) => {
            // This will try some values in the range of `$type`.
            for i in ($type::MIN..$type::MAX)
                .step_by(($type::MAX / 4 + 1) as usize)
                .chain(vec![$type::MAX])
            {
                test_encode_decode_tlv!(i as u64, $expected_len, Some(i), opt);
            }
        };
    }

    #[test]
    fn test_encode_decode_tlv() -> Result<(), DecodeError> {
        // All the Nones and empty vectors should have a length of zero.
        test_encode_decode_tlv!(1, 0, Option::<u8>::None, opt);
        test_encode_decode_tlv!(1, 0, Option::<u16>::None, opt);
        test_encode_decode_tlv!(1, 0, Option::<u32>::None, opt);
        test_encode_decode_tlv!(1, 0, Option::<u64>::None, opt);
        test_encode_decode_tlv!(1, 0, Option::<String>::None, opt);
        let v: Vec<u8> = Vec::new();
        test_encode_decode_tlv!(1, 0, v, vec);
        let v: Vec<Locator> = Vec::new();
        test_encode_decode_tlv!(1, 0, v, vec);
        let v: Vec<String> = Vec::new();
        test_encode_decode_tlv!(1, 0, v, vec);

        // Non-None primitives should have their in-memory byte length as follows.
        test_opt_ranged_type!(u8, 1);
        test_opt_ranged_type!(u16, 2);
        test_opt_ranged_type!(u32, 4);
        test_opt_ranged_type!(u64, 8);

        // Other types.
        let s = Some(String::from("teos"));
        test_encode_decode_tlv!(1, s.as_ref().unwrap().len() + 2, s, opt);
        test_encode_decode_tlv!(1, s.as_ref().unwrap().len(), s, opt_str);

        let v = vec![1_u8, 2, 3, 6];
        test_encode_decode_tlv!(1, v.len(), v, vec);

        let l = ser_utils::get_random_locator();
        let v = vec![l; 5];
        test_encode_decode_tlv!(1, v.len() * LOCATOR_LEN, v, vec);

        Ok(())
    }

    macro_rules! encode_decode_tlv_stream {
        ({$(($type: expr, $field_name: ident, $fieldty: tt)),* $(,)*}) => {{
            // Encode the TLVs to a stream.
            let mut stream = ser_utils::TestVecWriter(Vec::new());
            encode_tlv_stream!(&mut stream, {$(($type, $field_name, $fieldty)),*});
            // Re-initialize the fields to their default values before decoding.
            $(init_tlv_field_var!($field_name, $fieldty);)*
            // Decode with a reader with the writer's buffer.
            decode_tlv_stream!(io::Cursor::new(stream.0), {$(($type, $field_name, $fieldty)),*});
            ($($field_name),*)
        }};
    }

    macro_rules! test_encode_decode_tlv_stream {
        ({$(($type: expr, $field_name: ident, $field: expr, $fieldty: tt)),* $(,)*}) => {
            let original_stream = ($($field),*);
            #[allow(unused_assignments)]
            let decoded_stream = {
                // Initialize the fields we will read from. An unused_assignment happens here.
                $(init_tlv_field_var!($field_name, $fieldty);)*
                $($field_name = $field;)*
                encode_decode_tlv_stream!({$(($type, $field_name, $fieldty)),*})
            };
            assert_eq!(original_stream, decoded_stream, "The decoded stream doesn't match the original one");
        };
    }

    macro_rules! test_encode_decode_tlv_stream_should_panic {
        ($args: tt) => {
            // Allow unreachable patterns which happen when we have some non-unique tlv types.
            #[allow(unreachable_patterns)]
            // Runs `test_encode_decode_tlv_stream` inside a closure so that we don't need to
            // return a `Result<(), DecodeError` from the test functions.
            // `should_panic` tests must not return anything.
            (|| {
                test_encode_decode_tlv_stream!($args);
                Ok(())
            })()
            // Unwrap to panic on error.
            .unwrap();
        };
    }

    #[test]
    fn test_encode_decode_tlv_stream() -> Result<(), DecodeError> {
        test_encode_decode_tlv_stream!({
            (0, a, Option::<u32>::None, opt),
            (1, b, Some(3_u32), opt),
            (2, c, Some(String::from("teos")), opt),
            (31, d, Some(String::from("teos")), opt_str),
        });

        let l = ser_utils::get_random_locator();
        test_encode_decode_tlv_stream!({
            (12, a, vec![1_u32, 2, 3], vec),
            (24, b, Some(vec![1_u8, 2, 3]), opt),
            (31, c, vec!["one".to_owned(), "two".to_owned(), "3".to_owned()], vec),
            (59, d, Vec::<u32>::new(), vec),
            (78, e, vec![l; 4], vec),
        });

        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_encode_decode_tlv_stream_decreasing_type() {
        test_encode_decode_tlv_stream_should_panic!({
            (0, a, Some(0_u8), opt),
            (2, b, Some(1_u32), opt),
            (1, c, Vec::<u8>::new(), vec),
        });
    }

    #[test]
    #[should_panic]
    fn test_encode_decode_tlv_stream_non_increasing_type() {
        test_encode_decode_tlv_stream_should_panic!({
            (0, a, Some(0_u8), opt),
            (1, b, Some(1_u32), opt),
            (1, c, Vec::<u8>::new(), vec),
        });
    }

    #[test]
    fn test_set_msg_type() {
        struct Test1;
        set_msg_type!(Test1, 10);

        assert_eq!(Test1::TYPE, 10);
    }
}
