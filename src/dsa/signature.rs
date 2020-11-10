use rmath::bigint::BigInt;

/// (r, s)
pub struct SignatureContent {
    content: Vec<u8>,
    // in bytes
    r_len: usize,
    s_len: usize,
}

impl SignatureContent {
    pub fn new() -> Self {
        Self::with_capacity(1)
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            content: Vec::with_capacity(capacity),
            r_len: 0,
            s_len: 0,
        }
    }
    
    pub fn form_bigint(r: &BigInt, s: &BigInt) -> Self {
        let mut buf = Vec::new();
        buf.append(&mut r.to_be_bytes());
        let r_len = buf.len();
        buf.append(&mut s.to_be_bytes());
        let s_len = buf.len() - r_len;
        
        Self {
            content: buf,
            r_len,
            s_len,
        }
    }
    
    /// r, s
    pub fn to_bigint(&self) -> (BigInt, BigInt) {
        (BigInt::from_be_bytes(&self.content.as_slice()[0..self.r_len]),
        BigInt::from_be_bytes(&self.content.as_slice()[self.r_len..]))
    }
    
    pub fn set(&mut self, r: BigInt, s: BigInt) {
        self.content.clear();
        self.content.append(&mut r.to_be_bytes());
        self.r_len = self.content.len();
        self.content.append(&mut s.to_be_bytes());
        self.s_len = self.content.len() - self.r_len;
    }
}

impl AsRef<Vec<u8>> for SignatureContent {
    fn as_ref(&self) -> &Vec<u8> {
        &self.content
    }
}

impl AsMut<Vec<u8>> for SignatureContent {
    fn as_mut(&mut self) -> &mut Vec<u8> {
        &mut self.content
    }
}

impl AsRef<[u8]> for SignatureContent {
    fn as_ref(&self) -> &[u8] {
        self.content.as_slice()
    }
}

impl AsMut<[u8]> for SignatureContent {
    fn as_mut(&mut self) -> &mut [u8] {
        self.content.as_mut_slice()
    }
}
