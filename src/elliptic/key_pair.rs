use rmath::bigint::BigInt;

pub struct PublicKey {
    // public key Q: (qx,qy)
    pub(super) qx: BigInt,
    pub(super) qy: BigInt,
}

pub struct PrivateKey<> {
    pub(super) pk: PublicKey,
    pub(super) d: BigInt,
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
    pub fn new_uncheck(x: BigInt, y: BigInt) -> Self {
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
}

