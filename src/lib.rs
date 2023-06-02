use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic, Wordlist};
use ethers_core::{
    k256::{
        ecdsa::{signature::hazmat::PrehashSigner, SigningKey},
        elliptic_curve::FieldBytes,
        Secp256k1,
    },
    types::{
        transaction::{
            eip1559::Eip1559TransactionRequest as TransactionRequest, eip2718::TypedTransaction,
        },
        Address, Bytes, Signature, H256, U256,
    },
    utils::{hash_message, secret_key_to_address},
};

#[cfg(target_os = "android")]
pub fn init_logger() {
    use android_logger::Config;
    use log::LevelFilter;

    android_logger::init_once(Config::default().with_max_level(LevelFilter::Info));
}

#[cfg(not(target_os = "android"))]
pub fn init_logger() {
    let _ = env_logger::Builder::new().parse_filters("info").try_init();
}

pub fn impl_version() -> String {
    env!("ATB_CLI_IMPL_VERSION").to_owned()
}

const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";

pub type WalletResult<T, E = WalletError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("{0}")]
    DerivationParse(#[from] coins_bip32::Bip32Error),
    #[error("{0}")]
    Mnemonic(#[from] coins_bip39::MnemonicError),
    #[error("{0}")]
    Signature(#[from] k256::ecdsa::signature::Error),
    #[error("{0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Encrypt(anyhow::Error),
    #[error("{0}")]
    Decrypt(anyhow::Error),
    #[error("{0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Incorrect password")]
    WrongPassword,
    #[error("{0}")]
    EthSignature(#[from] ethers_core::types::SignatureError),
    #[error("{0}")]
    Provider(#[from] ProviderError),
    #[error("Insufficent gas for transaction")]
    InsufficientGasFunds,
}

pub fn ec_recover(signature: &[u8], message: &[u8]) -> WalletResult<String> {
    let sig: Signature = signature.try_into()?;
    let addr = sig.recover(message)?;
    Ok(format!("0x{:02x}", addr))
}

pub fn decrypt_json_bytes(
    encrypted_bytes: &[u8],
    password_bytes: &[u8],
    chain_id: u64,
) -> WalletResult<Arc<Wallet>> {
    log::info!(
        "[aethers] json payload: {}",
        String::from_utf8_lossy(encrypted_bytes)
    );
    log::info!(
        "[aethers] password: {}",
        String::from_utf8_lossy(password_bytes)
    );
    log::info!("[aethers] password bytes: {:?}", password_bytes);
    log::info!("[aethers] password length: {}", password_bytes.len(),);

    let store: keystore::Keystore = serde_json::from_slice(encrypted_bytes)?;
    let phrase_bytes = keystore::decrypt_key(store, password_bytes).map_err(|e| {
        log::info!("[aethers] error: {e}");
        WalletError::Decrypt(e)
    })?;
    let mnemonic = Mnemonic::<English>::new_from_phrase(std::str::from_utf8(&phrase_bytes)?)?;
    let inner = RwLock::new(WalletInner::new(
        mnemonic,
        String::from_utf8_lossy(password_bytes).to_string(),
        chain_id,
    )?);
    Ok(Arc::new(Wallet { inner }))
}

pub fn decrypt_json(
    encrypted: String,
    password: String,
    chain_id: u64,
) -> WalletResult<Arc<Wallet>> {
    decrypt_json_bytes(encrypted.as_bytes(), password.as_bytes(), chain_id)
}

pub fn from_mnemonic(
    mnemonic_string: String,
    password: String,
    chain_id: u64,
) -> WalletResult<Arc<Wallet>> {
    let mnemonic = Mnemonic::<English>::new_from_phrase(&mnemonic_string)?;
    let inner = RwLock::new(WalletInner::new(mnemonic, password, chain_id)?);
    Ok(Arc::new(Wallet { inner }))
}

pub struct Wallet {
    inner: RwLock<WalletInner<English>>,
}

struct WalletInner<T: Wordlist> {
    pub mnemonic: Mnemonic<T>,
    #[allow(dead_code)]
    pub index: usize,
    pub chain_id: u64,
    pub signer: SigningKey,
    pub address: Address,
    pub password: String,
}

impl<T: Wordlist> WalletInner<T> {
    pub fn new(mnemonic: Mnemonic<T>, password: String, chain_id: u64) -> WalletResult<Self> {
        let index = 0;
        let derivation_path =
            DerivationPath::from_str(&format!("{}{}", DEFAULT_DERIVATION_PATH_PREFIX, index))?;
        let derived_priv_key = mnemonic.derive_key(&derivation_path, None)?;
        let key: &coins_bip32::prelude::SigningKey = derived_priv_key.as_ref();
        let signer = SigningKey::from_bytes(&key.to_bytes())?;
        let address = secret_key_to_address(&signer);

        Ok(Self {
            mnemonic,
            chain_id,
            index,
            signer,
            address,
            password,
        })
    }
}

//#NOTE destroy() is created by the scaffolding, essentially a "free" of the memory holding the
//struct
impl Wallet {
    pub fn new(password: String, chain_id: u64) -> Self {
        let mut rng = rand::thread_rng();
        log::info!("[aethers] wallet: {password}");
        log::info!("[aethers] wallet bytes: {:?}", password.as_bytes());
        log::info!(
            "[aethers] wallet password length: {}",
            password.as_bytes().len()
        );

        let mnemonic = Mnemonic::<English>::new(&mut rng);
        let inner = RwLock::new(
            WalletInner::new(mnemonic, password, chain_id)
                .expect("default crypto bundle settings should succeed"),
        );

        Self { inner }
    }

    pub fn chain_id(&self) -> u64 {
        self.inner.read().unwrap().chain_id
    }

    pub fn request_accounts(&self) -> Vec<String> {
        vec![format!("0x{:02x}", self.inner.read().unwrap().address)]
    }

    pub fn sign_message(&self, message: &[u8]) -> WalletResult<String> {
        let message_hash = hash_message(message);
        let sig = self.sign_hash(message_hash, None)?;

        Ok(format!("{sig}"))
    }

    //https://github.com/metamask/eth-sig-util
    //this is a non-standard Metamask only signature implementation.  Not sure if we need to really
    //implement this given that the standard is moving towards EIP712
    // pub fn sign_personal_message() {}

    pub fn sign_typed_message(&self, payload: &[u8]) -> WalletResult<String> {
        let sig = self.sign_hash(H256::from_slice(payload), None)?;
        Ok(format!("{sig}"))
    }

    pub fn switch_chain() {}

    pub fn encrypt_json(&self) -> WalletResult<String> {
        let mut rng = rand::thread_rng();
        let inner = self.inner.read().unwrap();
        let mnemonic_string = inner.mnemonic.to_phrase();
        let password: &[u8] = inner.password.as_ref();
        keystore::encrypt_key(&mut rng, &mnemonic_string, password).map_err(WalletError::Encrypt)
    }

    pub fn recover_phrase(&self, password: String) -> WalletResult<String> {
        let inner = self.inner.read().unwrap();
        if password == *inner.password {
            Ok(inner.mnemonic.to_phrase())
        } else {
            Err(WalletError::WrongPassword)
        }
    }

    pub fn send_transaction(
        &self,
        provider: Arc<ChainProvider>,
        payload: String,
    ) -> WalletResult<String> {
        log::info!("[aethers] tx payload: {payload}");
        let inner = self.inner.read().unwrap();
        let address = inner.address;
        let mut request: TypedTransaction =
            serde_json::from_str::<TransactionRequest>(&payload)?.into();
        log::info!("[aethers] tx request: {request:?}");

        //#TODO convert to proper error
        assert_eq!(request.from(), Some(&address));

        let (sender_balance, gas_price, estimated_gas_used, chain_id) =
            provider.query_for_transaction(&request).map_err(|e| {
                log::info!("[aethers] query failed {e}");
                e
            })?;
        log::info!("[aethers] filling tx requirements. sender balance: {sender_balance:?}, gas_price: {gas_price:?}, estimated_gas_used: {estimated_gas_used:?}, chain_id: {chain_id:?}");
        //[aethers] filling tx requirements: 2000420000000000000, 100000000000, 36715, 13370

        // validity checks
        let total_value = (gas_price * estimated_gas_used)
            + request.value().map(|v| *v).unwrap_or_else(|| U256::zero());
        if sender_balance < total_value {
            return Err(WalletError::InsufficientGasFunds);
        }
        // //#TODO convert to proper error
        // assert_eq!(
        //     request.chain_id().map(|u| u.as_u64()),
        //     Some(chain_id.as_u64())
        // );

        let nonce = provider.get_transaction_count(address.clone())?;
        request
            .set_nonce(nonce)
            .set_gas(estimated_gas_used)
            .set_chain_id(inner.chain_id);

        //#NOTE this is nuanced, we are using the EIP1559TransactionRequest aliased to
        //TransactionRequest
        let mut tx_ref = request
            .as_eip1559_mut()
            .expect("its set up top a few lines, duh.");
        tx_ref.max_fee_per_gas = Some(gas_price);
        tx_ref.max_priority_fee_per_gas = Some(gas_price);

        let sig_hash = request.sighash();
        let sig = self.sign_hash(sig_hash, Some(inner.chain_id))?;

        log::info!("[aethers] sending raw transaction");
        provider
            .send_raw_transaction(request.rlp_signed(&sig))
            .map(|h| format!("0x{h:02x}"))
            .map_err(|e| {
                log::info!("[aethers] send tx error: {e}");
                e.into()
            })
    }

    /// Signs the provided hash.
    pub fn sign_hash(&self, hash: H256, chain_id: Option<u64>) -> Result<Signature, WalletError> {
        let inner = self.inner.read().unwrap();
        let (recoverable_sig, recovery_id) = inner.signer.sign_prehash(hash.as_ref())?;

        let v = u8::from(recovery_id) as u64
            + if let Some(chain_id) = chain_id {
                35 + chain_id * 2 //EIP155
            } else {
                27 //Homestead
            };

        let r_bytes: FieldBytes<Secp256k1> = recoverable_sig.r().into();
        let s_bytes: FieldBytes<Secp256k1> = recoverable_sig.s().into();
        let r = U256::from_big_endian(r_bytes.as_slice());
        let s = U256::from_big_endian(s_bytes.as_slice());

        Ok(Signature { r, s, v })
    }
}

use ethers_providers::{Http, Middleware, Provider};

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("runtime error")]
    Runtime(#[from] std::io::Error),
    #[error("parse error")]
    Parse,
    #[error("provider failed: {0}")]
    Inner(#[from] ethers_providers::ProviderError),
    #[error("from address is required for querying tx info")]
    FromAddressMissing,
}

pub fn provider_from_url(url: &str) -> Result<Arc<ChainProvider>, ProviderError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let provider = Provider::<Http>::try_from(url).map_err(|_| ProviderError::Parse)?;

    Ok(Arc::new(ChainProvider(RwLock::new(ProviderInner {
        rt,
        provider,
    }))))
}

pub struct ChainProvider(RwLock<ProviderInner>);
struct ProviderInner {
    rt: tokio::runtime::Runtime,
    provider: Provider<Http>,
}

impl ChainProvider {
    pub fn get_transaction_count(&self, address: Address) -> Result<U256, ProviderError> {
        let group = self.0.read().unwrap();
        group
            .rt
            .block_on(
                group
                    .provider
                    .get_transaction_count::<Address>(address.into(), None),
            )
            .map_err(ProviderError::from)
    }

    pub fn query_for_transaction(
        &self,
        tx: &TypedTransaction,
    ) -> Result<(U256, U256, U256, U256), ProviderError> {
        let group = self.0.read().unwrap();
        group.rt.block_on(async {
            let provider = &group.provider;

            let Some(from) = tx.from() else {
                    return Err(ProviderError::FromAddressMissing)
                };

            futures::try_join!(
                provider.get_balance(*from, None),
                provider.get_gas_price(),
                provider.estimate_gas(tx, None),
                provider.get_chainid(),
            )
            .map_err(ProviderError::from)
        })
    }

    pub fn send_raw_transaction(&self, tx: Bytes) -> Result<H256, ProviderError> {
        let group = self.0.read().unwrap();
        group.rt.block_on(async {
            let provider = &group.provider;

            provider
                .send_raw_transaction(tx)
                .await
                .map(|p| p.tx_hash())
                .map_err(Into::into)
        })
    }
}

include!(concat!(env!("OUT_DIR"), "/aethers.uniffi.rs"));

pub mod keystore {
    use aes::{
        cipher::{self, InnerIvInit, KeyInit, StreamCipherCore},
        Aes128,
    };
    use digest::{Digest, Update};
    // use ethereum_types::H160 as Address;
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use rand::{CryptoRng, Rng};
    use scrypt::{scrypt, Params as ScryptParams};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use sha3::Keccak256;
    use uuid::Uuid;

    const DEFAULT_CIPHER: &str = "aes-128-ctr";
    const DEFAULT_KEY_SIZE: usize = 32usize;
    const DEFAULT_IV_SIZE: usize = 16usize;
    const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
    const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
    const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
    const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

    pub fn encrypt_key<R, B, P>(rng: &mut R, pk: B, password: P) -> anyhow::Result<String>
    where
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        // Generate a random salt.
        let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
        rng.fill_bytes(salt.as_mut_slice());

        // Derive the key.
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )
        .map_err(|_e| anyhow::anyhow!("invalid scrypt params"))?;

        scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())
            .map_err(|_e| anyhow::anyhow!("script failed"))?;

        // Encrypt the private key using AES-128-CTR.
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        rng.fill_bytes(iv.as_mut_slice());
        let encryptor = Aes128Ctr::new(&key[..16], &iv[..16])
            .map_err(|_e| anyhow::anyhow!("invalid Aes128Ctr length"))?;
        let mut ciphertext = pk.as_ref().to_vec();
        encryptor.apply_keystream(&mut ciphertext);

        // Calculate the MAC.
        let mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&ciphertext)
            .finalize();

        // Construct and serialize the encrypted JSON keystore.
        let keystore = Keystore {
            id: Uuid::new_v4(),
            version: 3,
            crypto: CryptoJson {
                cipher: String::from(DEFAULT_CIPHER),
                cipherparams: CipherparamsJson { iv },
                ciphertext: ciphertext.to_vec(),
                kdf: KdfType::Scrypt,
                kdfparams: KdfparamsType::Scrypt {
                    dklen: DEFAULT_KDF_PARAMS_DKLEN,
                    n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                    p: DEFAULT_KDF_PARAMS_P,
                    r: DEFAULT_KDF_PARAMS_R,
                    salt,
                },
                mac: mac.to_vec(),
            },
            // address: eth::address_from_pk(&pk)?,
        };
        serde_json::to_string(&keystore).map_err(Into::into)
    }

    pub fn decrypt_key<P>(keystore: Keystore, password: P) -> anyhow::Result<Vec<u8>>
    where
        P: AsRef<[u8]>,
    {
        // Derive the key.
        let key = match keystore.crypto.kdfparams {
            KdfparamsType::Pbkdf2 {
                c,
                dklen,
                prf: _,
                salt,
            } => {
                let mut key = vec![0u8; dklen as usize];
                pbkdf2::<Hmac<Sha256>>(password.as_ref(), &salt, c, key.as_mut_slice());
                key
            }
            KdfparamsType::Scrypt {
                dklen,
                n,
                p,
                r,
                salt,
            } => {
                let mut key = vec![0u8; dklen as usize];
                let log_n = (n as f32).log2() as u8;
                let scrypt_params = ScryptParams::new(log_n, r, p)
                    .map_err(|_e| anyhow::anyhow!("invalid scrypt params"))?;
                scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())
                    .map_err(|_e| anyhow::anyhow!("scrypt failed"))?;
                key
            }
        };

        // Derive the MAC from the derived key and ciphertext.
        let derived_mac = Keccak256::new()
            .chain(&key[16..32])
            .chain(&keystore.crypto.ciphertext)
            .finalize();

        if derived_mac.as_slice() != keystore.crypto.mac.as_slice() {
            dbg!(derived_mac.as_slice());
            dbg!(keystore.crypto.mac.as_slice());
            log::info!("derived: {:?}", derived_mac.as_slice());
            log::info!("keystore: {:?}", keystore.crypto.mac.as_slice());
            return Err(anyhow::anyhow!("Mac mismatch"));
        }

        // Decrypt the private key bytes using AES-128-CTR
        let decryptor = Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv[..16])
            .map_err(|_e| anyhow::anyhow!("invalid Aes128Ctr length"))?;

        let mut pk = keystore.crypto.ciphertext;
        decryptor.apply_keystream(&mut pk);

        Ok(pk)
    }

    struct Aes128Ctr {
        inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
    }

    impl Aes128Ctr {
        fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
            let cipher = aes::Aes128::new_from_slice(key).unwrap();
            let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
            Ok(Self { inner })
        }

        fn apply_keystream(self, buf: &mut [u8]) {
            self.inner.apply_keystream_partial(buf.into());
        }
    }

    pub mod eth {
        use ethereum_types::H160 as Address;
        use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey};
        use sha3::{Digest, Keccak256};

        /// Converts a K256 SigningKey to an Ethereum Address
        pub fn address_from_pk<S>(pk: S) -> anyhow::Result<Address>
        where
            S: AsRef<[u8]>,
        {
            let secret_key = SigningKey::from_bytes(pk.as_ref().into())?;
            let public_key = PublicKey::from(secret_key.verifying_key());
            let public_key = public_key.to_encoded_point(/* compress = */ false);
            let public_key = public_key.as_bytes();
            debug_assert_eq!(public_key[0], 0x04);
            let hash = keccak256(&public_key[1..]);
            Ok(Address::from_slice(&hash[12..]))
        }

        /// Compute the Keccak-256 hash of input bytes.
        pub fn keccak256<S>(bytes: S) -> [u8; 32]
        where
            S: AsRef<[u8]>,
        {
            let mut hasher = Keccak256::new();
            hasher.update(bytes.as_ref());
            hasher.finalize().into()
        }
    }

    /// This struct represents the deserialized form of an encrypted JSON keystore based on the
    /// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
    #[derive(Debug, Deserialize, Serialize)]
    pub struct Keystore {
        // pub address: Address,
        pub crypto: CryptoJson,
        pub id: Uuid,
        pub version: u8,
    }

    /// Represents the "crypto" part of an encrypted JSON keystore.
    #[derive(Debug, Deserialize, Serialize)]
    pub struct CryptoJson {
        pub cipher: String,
        pub cipherparams: CipherparamsJson,
        #[serde(with = "buffer_as_hex")]
        pub ciphertext: Vec<u8>,
        pub kdf: KdfType,
        pub kdfparams: KdfparamsType,
        #[serde(with = "buffer_as_hex")]
        pub mac: Vec<u8>,
    }

    /// Represents the "cipherparams" part of an encrypted JSON keystore.
    #[derive(Debug, Deserialize, Serialize)]
    pub struct CipherparamsJson {
        #[serde(with = "buffer_as_hex")]
        pub iv: Vec<u8>,
    }

    /// Types of key derivition functions supported by the Web3 Secret Storage.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum KdfType {
        Pbkdf2,
        Scrypt,
    }

    /// Defines the various parameters used in the supported KDFs.
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(untagged)]
    pub enum KdfparamsType {
        Pbkdf2 {
            c: u32,
            dklen: u8,
            prf: String,
            #[serde(with = "buffer_as_hex")]
            salt: Vec<u8>,
        },
        Scrypt {
            dklen: u8,
            n: u32,
            p: u32,
            r: u32,
            #[serde(with = "buffer_as_hex")]
            salt: Vec<u8>,
        },
    }

    pub mod buffer_as_hex {
        use hex::{FromHex, ToHex};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: AsRef<[u8]>,
            S: Serializer,
        {
            serializer.serialize_str(&buffer.encode_hex::<String>())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            use serde::de::Error;
            String::deserialize(deserializer).and_then(|string| {
                Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string()))
            })
        }
    }
}
