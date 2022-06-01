


#[cfg(test)]
mod tests {
    pub struct Driver {
        /// Generate a shared key with your private/secret key and someone elses public key
        pub curve25519: unsafe extern "C" fn(
            mypublic: *mut curve25519_key, 
            secret: *mut curve25519_key, 
            basepoint: *mut curve25519_key
        ),

        /// Generate a public key from a secret key
        pub curve25519_basepoint: unsafe extern "C" fn(
            mypublic: *mut curve25519_key, 
            secret: *mut curve25519_key
        ),
    }

    /// Donna driver implementation (via FFI)
    #[cfg(feature = "build_donna")]
    pub const DONNA: Driver = Driver {
        curve25519: ffi::curve25519,
        curve25519_basepoint: ffi::curve25519_basepoint,
    };

    /// Dalek driver implementation (native rust)
    #[cfg(todo)]
    pub const DALEK: Driver = Driver {
        curve25519: todo!(),
        curve25519_basepoint: todo!(),
    };


}

