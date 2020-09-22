use std::error::Error;
use std::fmt::{Display, Formatter, Debug};
use crate::crypto_err::CryptoErrorKind::InvalidParameter;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CryptoErrorKind {
    InvalidParameter,
}

impl Debug for CryptoErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidParameter => write!(f, "{}", "InvalidParameter"),
        }
    }
}

#[derive(Debug)]
pub struct CryptoError {
    kind: CryptoErrorKind,
    err: Box<dyn std::error::Error + Sync + Send>,
}

impl CryptoError {
    pub fn new<E>(kind: CryptoErrorKind, err: E) -> CryptoError 
        where E: Into<Box<dyn Error + Sync + Send>>{
        CryptoError {
            kind,
            err: err.into(),
        }
    }
    
    pub fn kind(&self) -> CryptoErrorKind {
        self.kind
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}{}", self.kind, self.err)
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.err.source()
    }
}