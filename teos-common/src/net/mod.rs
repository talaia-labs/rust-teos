pub mod http;

use serde::Serialize;
use std::fmt;

/// Represents all types of teos network addresses
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
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

impl AddressType {
    pub fn get_type(net_addr: &str) -> AddressType {
        if net_addr.contains(".onion:") {
            AddressType::TorV3
        } else {
            AddressType::IpV4
        }
    }

    pub fn is_tor(&self) -> bool {
        self == &AddressType::TorV3
    }

    pub fn is_clearnet(&self) -> bool {
        self == &AddressType::IpV4
    }
}

#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
pub struct NetAddr {
    net_addr: String,
    #[serde(skip)]
    addr_type: AddressType,
}

impl NetAddr {
    pub fn new(net_addr: String) -> Self {
        NetAddr {
            addr_type: AddressType::get_type(&net_addr),
            net_addr,
        }
    }

    pub fn net_addr(&self) -> &str {
        &self.net_addr
    }

    pub fn addr_type(&self) -> &AddressType {
        &self.addr_type
    }

    pub fn is_onion(&self) -> bool {
        self.addr_type().is_tor()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const TORV3_ADDR: &str =
        "recnedb7xfhzjdrcgxongzli3a6qyrv5jwgowoho3v5g3rwk7kkglrid.onion:9814";
    pub const IPV4_ADDR: &str = "teos.talaia.watch:9814";

    #[test]
    fn test_get_type() {
        assert_eq!(AddressType::get_type(TORV3_ADDR), AddressType::TorV3);
        assert_eq!(AddressType::get_type(IPV4_ADDR), AddressType::IpV4);
    }

    #[test]
    fn test_is_tor() {
        assert!(NetAddr::new(TORV3_ADDR.to_owned()).addr_type.is_tor());
        assert!(!NetAddr::new(IPV4_ADDR.to_owned()).addr_type.is_tor());
    }

    #[test]
    fn test_is_clearnet() {
        assert!(!NetAddr::new(TORV3_ADDR.to_owned()).addr_type.is_clearnet());
        assert!(NetAddr::new(IPV4_ADDR.to_owned()).addr_type.is_clearnet());
    }
}
