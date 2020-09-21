use std::error::Error;
use std::fmt::{Display, Formatter, Debug};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CryptoErrorKind {
}

impl Debug for CryptoErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", stringify!(self))
    }
}

#[derive(Debug)]
pub struct CryptoError {
    kind: CryptoErrorKind,
    err: Box<dyn std::error::Error + Sync + Send>,
}

impl CryptoErrorKind {
    pub fn new<E>(kind: CryptoErrorKind, err: E) -> CryptoError 
        where E: Into<Box<dyn Error + Sync + Send>>{
        CryptoError {
            kind,
            err: err.into(),
        }
    }
    
    pub fn kind(&self) -> CryptoErrorKind {
        self.kind()
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl Error for CryptoError {
    fn source(&self) -> Option<&dyn Error + 'static> {
        unimplemented!()
    }
}