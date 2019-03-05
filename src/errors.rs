use std::fmt;

#[derive(Debug, Clone)]
pub struct Errors {
    pub val: i32, // Designed for C extension response
    pub reason: &'static str,
}

impl fmt::Display for Errors {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Error Val: {}, Reason: {}", self.val, self.reason)?;
        Ok(())
    }
}
