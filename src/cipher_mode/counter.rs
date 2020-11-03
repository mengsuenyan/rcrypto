//! The counter for CTR  

use crate::{CryptoError, CryptoErrorKind};

pub trait Counter {
    
    /// reset to the initial status
    fn reset(&mut self);
    
    fn next(&mut self) -> Option<&Vec<u8>>;
    
    fn bits_len(&self) -> usize;
}

pub struct DefaultCounter {
    bits_len: usize,
    initial_val: Vec<u8>,
    cur_val: Option<Vec<u8>>,
}

impl Clone for DefaultCounter {
    fn clone(&self) -> Self {
        Self {
            bits_len: self.bits_len,
            initial_val: self.initial_val.clone(),
            cur_val: None,
        }
    }
}

impl DefaultCounter {
    pub fn new(initial_val: Vec<u8>, bits_len: usize) -> Result<Self, CryptoError> {
        if ((bits_len + 7) >> 3) < initial_val.len() {
            Err(CryptoError::new(CryptoErrorKind::InvalidParameter, 
                format!("bits_len need to less than the bits length of initial_vec")))
        } else {
            Ok(
                Self {
                    bits_len,
                    initial_val,
                    cur_val: None,
                }
            )
        }
    }
}

impl Counter for DefaultCounter {
    fn reset(&mut self) {
        self.cur_val.take();
    }

    fn next(&mut self) -> Option<&Vec<u8>> {
        if self.cur_val.is_none() {
            let len = (self.bits_len + 7) >> 3;
            let mut v = Vec::with_capacity(len);
            v.resize(len.saturating_sub(self.initial_val.len()), 0);
            v.extend(self.initial_val.iter().take(len - len.saturating_sub(self.initial_val.len())));
            self.cur_val = Some(v);
        } else {
            //note: here is not to handle the overflowing
            let v = self.cur_val.as_mut().unwrap();
            let mut c = 1;
            v.iter_mut().rev().for_each(|a| {
                let (x, y) = (*a).overflowing_add(c);
                c = if y {1} else {0};
                *a = x;
            });
        }
        
        self.cur_val.as_ref()
    }

    fn bits_len(&self) -> usize {
        self.bits_len
    }
}