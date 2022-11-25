use std::fmt;

/// Represents all types of teos network addresses
pub enum AddressType {
    IpV4 = 0,
    TorV3 = 1,
}

impl From<i32> for AddressType {
    fn from(x: i32) -> Self {
        match x {
            0 => AddressType::IpV4,
            1 => AddressType::TorV3,
            x => panic!("Unknown address type {}", x),
        }
    }
}

impl std::str::FromStr for AddressType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ipv4" => Ok(AddressType::IpV4),
            "torv3" => Ok(AddressType::TorV3),
            _ => Err(format!("Unknown type: {}", s)),
        }
    }
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            AddressType::IpV4 => "ipv4",
            AddressType::TorV3 => "torv3",
        };
        write!(f, "{}", s)
    }
}
