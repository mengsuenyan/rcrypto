use std::error::Error;
use std::fmt::{Display, Formatter, Debug};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CryptoErrorKind {
    InvalidParameter,
    NotSupportUsage,
    RandError,
    UnpaddingNotMatch,
}

impl Debug for CryptoErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoErrorKind::InvalidParameter => write!(f, "{}", "InvalidParameter"),
            CryptoErrorKind::NotSupportUsage => write!(f, "{}", "NotSupportUsage"),
            CryptoErrorKind::RandError => write!(f, "{}", "RandError"),
            CryptoErrorKind::UnpaddingNotMatch => write!(f, "{}", "UnpaddingNotMatch"),
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