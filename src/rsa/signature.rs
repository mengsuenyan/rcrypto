
#[derive(Clone)]
pub struct SignatureContent {
    content: Vec<u8>,
}

impl SignatureContent {
    pub fn new() -> Self {
        Self {
            content: Vec::new()
        }
    }
    
    pub fn with_capacity(capacity: usize) -> Self {
        SignatureContent {
            content: Vec::with_capacity(capacity)
        }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl From<&[u8]> for SignatureContent {
    fn from(content: &[u8]) -> Self {
        let mut buf = Vec::with_capacity(content.len());
        buf.extend(content.iter());
        Self {
            content: buf,
        }
    }
}

impl From<Vec<u8>> for SignatureContent {
    fn from(content: Vec<u8>) -> Self {
        Self {
            content,
        }
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

