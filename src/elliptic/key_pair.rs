use rmath::bigint::BigInt;

pub struct PublicKey {
    // public key Q: (qx,qy)
    pub(crate) qx: BigInt,
    pub(crate) qy: BigInt,
}

pub struct PrivateKey {
    pub(crate) pk: PublicKey,
    pub(crate) d: BigInt,
}

pub struct KeyPair {
    pub_key: Option<PublicKey>,
    pri_key: Option<PrivateKey>,
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self {
            qx: self.qx.deep_clone(),
            qy: self.qy.deep_clone(),
        }
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            d: self.d.clone(),
        }
    }
}

impl PublicKey {
    pub fn new_uncheck(x: &BigInt, y: &BigInt) -> Self {
        Self {
            qx: x.deep_clone(),
            qy: y.deep_clone(),
        }
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    
    pub fn new_uncheck(pk: PublicKey, d: &BigInt) -> Self {
        Self {
            pk,
            d: d.deep_clone(),
        }
    }
}

impl From<PrivateKey> for KeyPair {
    fn from(pk: PrivateKey) -> Self {
        Self {
            pub_key: None,
            pri_key: Some(pk),
        }
    }
}


impl From<PublicKey> for KeyPair {
    fn from(pk: PublicKey) -> Self {
        Self {
            pub_key: Some(pk),
            pri_key: None,
        }
    }
}

impl KeyPair {
    pub fn public_key(&self) -> &PublicKey {
        if self.pri_key.is_some() {
            self.pri_key.as_ref().unwrap().public_key()
        } else {
            self.pub_key.as_ref().unwrap()
        }
    }
    
    pub fn private_key(&self) -> Option<&PrivateKey> {
        self.pri_key.as_ref()
    }
}