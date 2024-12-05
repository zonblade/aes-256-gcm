//!
//! Inspired by simplicity of (let's say JWT) this crate provide high-level
//! abstraction for AES-GCM Crate with some enhancement such as expiration check
//!
//! for detailed usage, please refer to the readme and example in the repository
//!
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    aes::{
        cipher::typenum::{
            bit::{B0, B1},
            UInt, UTerm,
        },
        Aes256,
    },
    AeadCore, Aes256Gcm, AesGcm as AG,
};

type AesGcm = AG<
    Aes256,
    UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>,
    UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>,
>;
type AesGeneric = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;
type AesClient = AesGcm;

#[derive(Debug, PartialEq, PartialOrd, Eq)]
pub enum AesErrorCode {
    EncryptDataNotValid,
    EncryptOptionError,
    EncryptFailed,

    DecryptDataNotValid,
    DecryptStringConvention,

    Expired,
}

#[derive(Debug)]
pub struct AesError {
    pub code: AesErrorCode,
    pub note: &'static str,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct AesOptions {
    expire: Option<String>,
}

impl AesOptions {
    pub fn with_expire_second(expire: i64) -> Self {
        let microsecond = expire * 1_000_000;
        let expire = chrono::Utc::now() + chrono::Duration::microseconds(microsecond);
        let expire = expire.to_rfc3339();
        Self {
            expire: Some(expire),
        }
    }

    pub fn with_expire_date(expire: chrono::DateTime<chrono::Utc>) -> Self {
        let expire = expire.to_rfc3339();
        Self {
            expire: Some(expire),
        }
    }

    pub fn build(self) -> AesOptions {
        self
    }
}

#[derive(Clone)]
pub struct Client {
    client: AesClient,
}

impl Client {
    pub fn new<'a>(secret: impl Into<Option<&'a str>>) -> Self {
        let data: Option<&'a str> = secret.into();

        let aes_secret = match data {
            Some(d) => Some(d.to_string()),
            None => None,
        };

        let aes_secret = match aes_secret {
            Some(data) => data,
            None => {
                let env = std::env::var("AES_GCM_SECRET").expect(
                    "if you are not using parameter, AES_GCM_SECRET os ENV must present or fill the Client::new(secret) parameter"
                );
                env
            }
        };

        let mut aes_secret = aes_secret.as_bytes().to_vec();
        if aes_secret.len() > 32 {
            aes_secret.truncate(32);
        } else {
            while aes_secret.len() < 32 {
                aes_secret.push(0);
            }
        }
        let aes_key = GenericArray::from_slice(&aes_secret);
        let client: AesClient = Aes256Gcm::new(&aes_key);
        Self { client }
    }

    pub fn encrypt<T>(
        &self,
        data: T,
        option: impl Into<Option<AesOptions>>,
    ) -> Result<String, AesError>
    where
        T: serde::Serialize,
    {
        let data = match serde_json::to_string(&data) {
            Ok(data) => data,
            Err(_) => return Err(AesError {
                code: AesErrorCode::EncryptDataNotValid,
                note:
                    "Data of encryption is not valid data, data must be able to serialize to json",
            }),
        };
        let mut opt = String::new();
        let optx: Option<AesOptions> = option.into();
        if let Some(optn) = optx {
            let json_opt = match serde_json::to_string(&optn) {
                Ok(data) => data,
                Err(_) => {
                    return Err(AesError {
                        code: AesErrorCode::EncryptOptionError,
                        note: "Option failed to build, please check correct parameter",
                    })
                }
            };
            opt = json_opt;
        }
        let data = format!("{}::{}", data, opt);
        let data = data.as_bytes();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypt = match self.client.encrypt(&nonce, data.as_ref()) {
            Ok(data) => data,
            Err(_) => {
                return Err(AesError {
                    code: AesErrorCode::EncryptFailed,
                    note: "Failed to encrypt data, please check correct parameter",
                })
            }
        };
        let nonce = nonce
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        let data = encrypt
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>();
        let data = format!("{}{}", data, nonce);
        Ok(data)
    }

    pub fn decrypt<'a, T>(&self, data: &'a str) -> Result<T, AesError>
    where
        for<'de> T: serde::Deserialize<'de>,
    {
        let (data, nonce) = data.split_at(data.len() - 24);
        let nonce = nonce
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|x| x.iter().collect::<String>())
            .map(|x| u8::from_str_radix(&x, 16).unwrap_or(0))
            .collect::<AesGeneric>();
        let data = data
            .chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|x| x.iter().collect::<String>())
            .map(|x| u8::from_str_radix(&x, 16).unwrap_or(0))
            .collect::<Vec<u8>>();
        let decrypt = match self.client.decrypt(&nonce, data.as_ref()) {
            Ok(data) => data,
            Err(_) => {
                return Err(AesError {
                    code: AesErrorCode::DecryptDataNotValid,
                    note: "Input data or token does not have valid encryption data",
                })
            }
        };
        // to string
        let str_decrypt = match std::str::from_utf8(&decrypt) {
            Ok(data) => data,
            Err(_) => {
                return Err(AesError {
                    code: AesErrorCode::DecryptStringConvention,
                    note:
                        "String convention failed, either it is not valid string or not utf8 string",
                })
            }
        };
        let str_decrypt: Vec<&str> = str_decrypt.split("::").collect();
        let decrypt = str_decrypt[0];
        // decrypt to byte
        let decrypt = decrypt.as_bytes();

        if str_decrypt.len() > 1 {
            let option_decrypt = str_decrypt[1].as_bytes();
            let data_expiry = match serde_json::from_slice::<AesOptions>(&option_decrypt) {
                Ok(data) => data,
                Err(_) => AesOptions { expire: None },
            };

            if let Some(expire) = data_expiry.expire {
                let date_now = chrono::Utc::now();
                let date_exp = chrono::DateTime::parse_from_rfc3339(&expire);
                match date_exp {
                    Ok(date_exp) => {
                        if date_now > date_exp {
                            return Err(AesError {
                                code: AesErrorCode::Expired,
                                note: "This data/token simply expired",
                            });
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        let data = match serde_json::from_slice::<T>(&decrypt) {
            Ok(data) => data,
            Err(_) => {
                return Err(AesError {
                    code: AesErrorCode::DecryptDataNotValid,
                    note: "Data of decryption is not valid encrypted data",
                })
            }
        };
        Ok(data)
    }
}

#[allow(dead_code)]
fn main() {}

#[cfg(test)]
mod tests {
    use super::*;

    ///
    /// Test case 1 \
    /// Simple encrypt and decrypt string
    ///
    #[test]
    fn test_case_1() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            let client = Client::new(None);
            let encrypted = client.encrypt("my thing", None);
            let decrypted: String = client.decrypt(&encrypted.unwrap()).unwrap();
            assert_eq!(decrypted, "my thing");
        });

    }

    ///
    /// Test case 2 \
    /// Simple encrypt and decrypt struct
    ///
    #[test]
    fn test_case_2() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
            struct TestCase2 {
                pub name: String,
            }

            let client = Client::new(None);
            let data = TestCase2 {
                name: "my name".to_string(),
            };

            let encrypted = client.encrypt(&data, None);
            let decrypted: TestCase2 = client.decrypt(&encrypted.unwrap()).unwrap();
            assert_eq!(decrypted, data);
        });
    }

    ///
    /// Test case 3 \
    /// Simple encrypt and decrypt string with expire
    ///
    #[test]
    fn test_case_3() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            let client = Client::new(None);
            let encrypted = client.encrypt("my thing", AesOptions::with_expire_second(3).build());
            // sleep 5 second
            std::thread::sleep(std::time::Duration::from_secs(2));
            let decrypted = client.decrypt::<String>(&encrypted.unwrap());
            if let Ok(data) = decrypted {
                assert_eq!(data, "my thing");
            } else {
                assert!(false);
            }
        });
    }

    ///
    /// Test case 4 \
    /// Simple encrypt and decrypt string with expire
    ///
    #[test]
    fn test_case_4() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            let client = Client::new(None);
            let encrypted = client.encrypt("my thing", AesOptions::with_expire_second(3).build());
            // sleep 5 second
            std::thread::sleep(std::time::Duration::from_secs(4));
            let decrypted = client.decrypt::<String>(&encrypted.unwrap());
            if let Err(e) = decrypted {
                assert_eq!(e.code, AesErrorCode::Expired);
            } else {
                assert!(false);
            }
        });
    }

    ///
    /// Test case 5 \
    /// Simple encrypt and decrypt struct with expire
    ///
    #[test]
    fn test_case_5() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
            struct TestCase2 {
                pub name: String,
            }

            let client = Client::new(None);
            let data = TestCase2 {
                name: "my name".to_string(),
            };
            let encrypted = client.encrypt(data, AesOptions::with_expire_second(3).build());
            // sleep 5 second
            std::thread::sleep(std::time::Duration::from_secs(2));
            let decrypted = client.decrypt::<TestCase2>(&encrypted.unwrap());
            if let Ok(data) = decrypted {
                assert_eq!(
                    data,
                    TestCase2 {
                        name: "my name".to_string()
                    }
                );
            } else {
                assert!(false);
            }
        });
    }

    ///
    /// Test case 6 \
    /// Simple encrypt and decrypt struct with expire
    ///
    #[test]
    fn test_case_6() {
        temp_env::with_var("AES_GCM_SECRET", Some("some key"), || {
            #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
            struct TestCase2 {
                pub name: String,
            }

            let client = Client::new(None);
            let data = TestCase2 {
                name: "my name".to_string(),
            };
            let encrypted = client.encrypt(data, AesOptions::with_expire_second(3).build());
            // sleep 5 second
            std::thread::sleep(std::time::Duration::from_secs(4));
            let decrypted = client.decrypt::<TestCase2>(&encrypted.unwrap());
            if let Err(e) = decrypted {
                assert_eq!(e.code, AesErrorCode::Expired);
            } else {
                assert!(false);
            }
        });
    }

    ///
    /// Test case 7
    /// secret with &str
    ///
    #[test]
    fn test_case_7() {
        // remove os env
        std::env::remove_var("AES_GCM_SECRET");
        let secrets = "my secret";
        let client = Client::new(secrets);
        let encrypted = client.encrypt("my thing", None);
        let decrypted: String = client.decrypt(&encrypted.unwrap()).unwrap();
        assert_eq!(decrypted, "my thing");
    }

    ///
    /// Test case 8
    /// secret with String
    ///
    #[test]
    fn test_case_8() {
        std::env::remove_var("AES_GCM_SECRET");
        let secrets = String::from("my secret");
        let client = Client::new(&*secrets);
        let encrypted = client.encrypt("my thing", None);
        let decrypted: String = client.decrypt(&encrypted.unwrap()).unwrap();
        assert_eq!(decrypted, "my thing");
    }

    ///
    /// Test case 9
    /// no secret and no env
    ///
    #[test]
    #[should_panic]
    fn test_case_9() {
        std::env::remove_var("AES_GCM_SECRET");
        // expect it to be panic
        Client::new(None);
    }
}
