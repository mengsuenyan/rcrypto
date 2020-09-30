macro_rules! impl_cipher {
    ($Type0: ident) => {
        impl<C, P> Cipher for $Type0<C, P>
            where C: Cipher, P: 'static + Padding {
            fn block_size(&self) -> Option<usize> {
                self.ecb.block_size()
            }
        
            fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
                self.ecb.encrypt(dst, plaintext_block)
            }
        
            fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
                self.ecb.decrypt(dst, cipher_block)
            }
        }
    };
}

macro_rules! impl_fn_reset {
    ($Type0: ident) => {
        impl<C, P> $Type0<C, P> 
            where C: Cipher, P: 'static + Padding {
            
            pub fn reset(&mut self) {
                self.data.clear();
                self.pond.clear();
            }
        }
    };
}

