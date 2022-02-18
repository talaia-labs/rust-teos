/// General errors [1, 32]
pub const MISSING_FIELD: u8 = 1;
pub const EMPTY_FIELD: u8 = 2;
pub const WRONG_FIELD_TYPE: u8 = 3;
pub const WRONG_FIELD_SIZE: u8 = 4;
pub const WRONG_FIELD_FORMAT: u8 = 5;
pub const INVALID_REQUEST_FORMAT: u8 = 6;
pub const INVALID_SIGNATURE_OR_SUBSCRIPTION_ERROR: u8 = 7;
pub const SERVICE_UNAVAILABLE: u8 = 32;

/// Appointment errors [33, 64]
pub const APPOINTMENT_FIELD_TOO_SMALL: u8 = 33;
pub const APPOINTMENT_FIELD_TOO_BIG: u8 = 34;
pub const APPOINTMENT_ALREADY_TRIGGERED: u8 = 35;
pub const APPOINTMENT_NOT_FOUND: u8 = 36;

/// Registration errors [65, 96]
pub const REGISTRATION_RESOURCE_EXHAUSTED: u8 = 65;

/// UNHANDLED
pub const UNEXPECTED_ERROR: u8 = 255;
