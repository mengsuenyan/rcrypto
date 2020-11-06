macro_rules! impl_cipher {
    ($Type0: ident, $INS: ident) => {
        impl<C, P> Cipher for $Type0<C, P>
            where C: Cipher, P: 'static + Padding {
            type Output = usize;
            fn block_size(&self) -> Option<usize> {
                self.$INS.block_size()
            }
        
            fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.encrypt(dst, plaintext_block)
            }
        
            fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.decrypt(dst, cipher_block)
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

macro_rules! impl_cipher_iv {
    ($Type0: ident, $INS: ident) => {
        impl<C, P, IV> Cipher for $Type0<C, P, IV>
            where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
            type Output = usize;
            fn block_size(&self) -> Option<usize> {
                self.$INS.block_size()
            }
        
            fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.encrypt(dst, plaintext_block)
            }
        
            fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.decrypt(dst, cipher_block)
            }
        }
    };
}

macro_rules! impl_fn_reset_iv {
    ($Type0: ident, $IN: ident) => {
        impl<C, P, IV> $Type0<C, P, IV> 
            where C: Cipher, P: 'static + Padding, IV: InitialVec<C> {
            
            pub fn reset(&mut self) {
                self.data.clear();
                self.pond.clear();
                self.ij.clear();
                self.ij.extend(self.$IN.cur_iv.iter());
            }
        }
    };
}

macro_rules! impl_cipher_ofb {
    ($Type0: ident, $INS: ident) => {
        impl<C, IV> Cipher for $Type0<C, IV>
            where C: Cipher, IV: InitialVec<C> {
            type Output = usize;
            fn block_size(&self) -> Option<usize> {
                self.$INS.block_size()
            }
        
            fn encrypt(&self, dst: &mut Vec<u8>, plaintext_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.encrypt(dst, plaintext_block)
            }
        
            fn decrypt(&self, dst: &mut Vec<u8>, cipher_block: &[u8]) -> Result<usize, CryptoError> {
                self.$INS.decrypt(dst, cipher_block)
            }
        }
    };
}

macro_rules! impl_fn_reset_ofb {
    ($Type0: ident) => {
        impl<C, IV> $Type0<C, IV> 
            where C: Cipher, IV: InitialVec<C> {
            
            pub fn reset(&mut self) {
                self.data.clear();
                self.pond.clear();
                self.ij.clear();
                self.ij.extend(self.ofb.cur_iv.iter());
            }
        }
    };
}

