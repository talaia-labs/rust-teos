use core::fmt::Debug;
use lightning_invoice::Invoice;

/// This trait specifies the functionality that needs to be implemented to
/// accept and validate a payment from a user.
pub trait ValidatePayment {
    // Generates an invoice for the user to pay.
    fn get_invoice(&self) -> Invoice;
    // Validates that the payment was paid.
    fn validate(&self, invoice: Invoice) -> bool;
}

impl Debug for dyn ValidatePayment + std::marker::Send + 'static {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hello")
    }
}
