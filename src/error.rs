use alloy_dyn_abi::JsonAbiExt;
use alloy_json_abi::Error as AlloyError;
use alloy_primitives::hex::{decode, encode, encode_prefixed, FromHexError};
use alloy_primitives::U256;
use ethers::providers::RpcError;
use once_cell::sync::Lazy;
use reqwest::{Client, Error as ReqwestError};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};
use thiserror::Error;

pub const SELECTOR_REGISTRY_URL: &str = "https://api.openchain.xyz/signature-database/v1/lookup";

// panic selector
pub const PANIC_SIG: &str = "Panic(uint256)";
pub const PANIC_SELECTOR: [u8; 4] = [0x4e, 0x48, 0x7b, 0x71]; // 0x4e487b71

/// hashmap of cached error selectors
pub static SELECTORS: Lazy<Mutex<HashMap<[u8; 4], AlloyError>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Error)]
pub enum AbiDecodedErrorType {
    Unknown(Vec<u8>),
    Known {
        name: String,
        args: Vec<String>,
        sig: String,
        data: Vec<u8>,
    },
}

impl From<AbiDecodedErrorType> for String {
    fn from(value: AbiDecodedErrorType) -> Self {
        value.to_string()
    }
}

impl std::fmt::Display for AbiDecodedErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AbiDecodedErrorType::Unknown(data) => f.write_str(&format!(
                "Execution reverted with unknown error. Data: {:?} ",
                encode(data)
            )),
            AbiDecodedErrorType::Known { name, args, .. } => f.write_str(&format!(
                "Execution reverted with error: {}\n{}",
                name,
                args.join("\n")
            )),
        }
    }
}

impl AbiDecodedErrorType {
    pub async fn retrieve_from_cache(
        selector_hash: [u8; 4],
    ) -> Result<Option<AlloyError>, AbiDecodeFailedErrors> {
        let selectors = SELECTORS.lock()?;
        Ok(selectors.get(&selector_hash).cloned())
    }

    /// decodes an error returned from calling a contract by searching its selector in registry
    pub async fn selector_registry_abi_decode(
        error_data: &[u8],
    ) -> Result<Self, AbiDecodeFailedErrors> {
        if error_data.is_empty() {
            return Err(AbiDecodeFailedErrors::NoData);
        }
        if error_data.len() < 4 {
            return Err(AbiDecodeFailedErrors::InvalidSelectorHash(
                error_data.to_vec(),
            ));
        }
        let (hash_bytes, args_data) = error_data.split_at(4);
        let selector_hash = alloy_primitives::hex::encode_prefixed(hash_bytes);
        let selector_hash_bytes: [u8; 4] = hash_bytes
            .try_into()
            .map_err(|_| AbiDecodeFailedErrors::InvalidSelectorHash(hash_bytes.to_vec()))?;

        // check if the error is Panic and return early if so
        if let Some(result) = Self::decode_panic(selector_hash_bytes, args_data) {
            return Ok(result);
        }

        // check if selector already is cached
        let cached_selector = Self::retrieve_from_cache(selector_hash_bytes).await?;
        if let Some(error) = cached_selector {
            if let Ok(result) = error.abi_decode_input(args_data, false) {
                return Ok(AbiDecodedErrorType::Known {
                    name: error.name.to_string(),
                    args: result.iter().map(|v| format!("{:?}", v)).collect(),
                    sig: error.signature(),
                    data: error_data.to_vec(),
                });
            }
            return Ok(Self::Unknown(error_data.to_vec()));
        }

        let client = Client::builder().build()?;
        let response = client
            .get(SELECTOR_REGISTRY_URL)
            .query(&vec![
                ("function", selector_hash.as_str()),
                ("filter", "true"),
            ])
            .header("accept", "application/json")
            .send()
            .await?
            .json::<Value>()
            .await?;

        if let Some(selectors) = response["result"]["function"][selector_hash].as_array() {
            for opt_selector in selectors {
                if let Some(selector) = opt_selector["name"].as_str() {
                    if let Ok(error) = selector.parse::<AlloyError>() {
                        if let Ok(result) = error.abi_decode_input(args_data, false) {
                            // cache the fetched selector
                            {
                                let mut cached_selectors = SELECTORS.lock()?;
                                cached_selectors.insert(selector_hash_bytes, error.clone());
                            };
                            return Ok(Self::Known {
                                sig: error.signature(),
                                name: error.name,
                                args: result.iter().map(|v| format!("{:?}", v)).collect(),
                                data: error_data.to_vec(),
                            });
                        }
                    }
                }
            }
            Ok(Self::Unknown(error_data.to_vec()))
        } else {
            Ok(Self::Unknown(error_data.to_vec()))
        }
    }

    /// Decodes an error by checking if it is a Panic(uint256) and returns `None` if
    /// it is not and returns `Some(Self::Known)` if it is, with decoding error args
    /// into the reason specified in specs:
    ///
    /// https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require
    pub fn decode_panic(selector: [u8; 4], data: &[u8]) -> Option<Self> {
        if selector == PANIC_SELECTOR {
            let arg = U256::try_from_be_slice(data)?;
            let reason = match arg {
                v if v == U256::from(0x00) => "generic compiler inserted panics",
                v if v == U256::from(0x01) => "asserted with an argument that evaluates to false",
                v if v == U256::from(0x11) => "an arithmetic operation resulted in underflow or overflow outside of an unchecked { ... } block",
                v if v == U256::from(0x12) => "divide or modulo by zero (e.g. 5 / 0 or 23 % 0)",
                v if v == U256::from(0x21) => "converted a value that is too big or negative into an enum type",
                v if v == U256::from(0x22) => "accessed a storage byte array that is incorrectly encoded",
                v if v == U256::from(0x31) => "called .pop() on an empty array",
                v if v == U256::from(0x32) => "accessed an array, bytesN or an array slice at an out-of-bounds or negative index (i.e. x[i] where i >= x.length or i < 0)",
                v if v == U256::from(0x41) => "allocated too much memory or created an array that is too large",
                v if v == U256::from(0x51) => "called a zero-initialized variable of internal function type",
                _ => "unknown",
            };
            Some(Self::Known {
                name: format!(
                    "Panic, reason: {}, (code: {})",
                    reason,
                    encode_prefixed(arg.to_be_bytes_trimmed_vec()),
                ),
                args: vec![format!("{:?}", arg)],
                sig: PANIC_SIG.to_string(),
                data: data.to_vec(),
            })
        } else {
            None
        }
    }
}

impl AbiDecodedErrorType {
    pub async fn try_from_provider_error(
        err: impl RpcError,
    ) -> Result<Self, AbiDecodeFailedErrors> {
        let err = err.as_error_response();
        if let Some(err) = err {
            if let Some(data) = &err.data {
                if let Some(data) = data.as_str() {
                    Ok(Self::selector_registry_abi_decode(&decode(data)?).await?)
                } else {
                    Ok(Self::Unknown(vec![]))
                }
            } else {
                Ok(Self::Unknown(vec![]))
            }
        } else {
            Ok(Self::Unknown(vec![]))
        }
    }
}

#[derive(Debug, Error)]
pub enum AbiDecodeFailedErrors {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("Invalid Error Selector: {0:?}")]
    InvalidSelectorHash(Vec<u8>),
    #[error("Selectors Cache Poisoned")]
    SelectorsCachePoisoned,
    #[error(transparent)]
    HexDecodeError(#[from] FromHexError),
    #[error("No Error Data")]
    NoData,
}

impl<'a> From<PoisonError<MutexGuard<'a, HashMap<[u8; 4], AlloyError>>>> for AbiDecodeFailedErrors {
    fn from(_value: PoisonError<MutexGuard<'a, HashMap<[u8; 4], AlloyError>>>) -> Self {
        Self::SelectorsCachePoisoned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::providers::{JsonRpcError, MockError};
    use serde_json::json;

    #[tokio::test]
    async fn test_error_decoder() {
        let data = vec![26, 198, 105, 8];
        let res = AbiDecodedErrorType::selector_registry_abi_decode(&data.clone())
            .await
            .expect("failed to get error selector");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name: "UnexpectedOperandValue".to_owned(),
                args: vec![],
                sig: "UnexpectedOperandValue()".to_owned(),
                data
            },
            res
        );
    }

    #[tokio::test]
    async fn test_error_decoder_unknown() {
        let data = vec![26, 198, 105, 9];
        let res = AbiDecodedErrorType::selector_registry_abi_decode(&data.clone())
            .await
            .expect("failed to get error selector");
        assert_eq!(AbiDecodedErrorType::Unknown(data), res);
    }

    #[tokio::test]
    async fn test_error_decoder_invalid_selector() {
        let data = vec![26, 198, 105];
        let res = AbiDecodedErrorType::selector_registry_abi_decode(&data.clone())
            .await
            .expect_err("expected error");
        match res {
            AbiDecodeFailedErrors::InvalidSelectorHash(_) => {}
            _ => panic!("unexpected error"),
        }
    }

    #[tokio::test]
    async fn test_error_decoder_no_data() {
        let data = vec![];
        let res = AbiDecodedErrorType::selector_registry_abi_decode(&data.clone())
            .await
            .expect_err("expected error");
        match res {
            AbiDecodeFailedErrors::NoData => {}
            _ => panic!("unexpected error"),
        }
    }

    #[tokio::test]
    async fn test_error_decoder_cache() {
        let data = vec![26, 198, 105, 8];
        let res = AbiDecodedErrorType::selector_registry_abi_decode(&data.clone())
            .await
            .expect("failed to get error selector");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name: "UnexpectedOperandValue".to_owned(),
                args: vec![],
                sig: "UnexpectedOperandValue()".to_owned(),
                data: data.clone()
            },
            res
        );

        let res = AbiDecodedErrorType::retrieve_from_cache(data.as_slice().try_into().unwrap())
            .await
            .expect("failed to get error selector");
        assert_eq!(
            Some(AlloyError {
                name: "UnexpectedOperandValue".into(),
                inputs: vec![]
            }),
            res
        );

        let data = vec![26, 198, 105, 9];
        let res = AbiDecodedErrorType::retrieve_from_cache(data.as_slice().try_into().unwrap())
            .await
            .unwrap();
        assert_eq!(None, res);
    }

    #[tokio::test]
    async fn test_error_decoder_provider_error() {
        let data = vec![26, 198, 105, 8];
        let res =
            AbiDecodedErrorType::try_from_provider_error(MockError::JsonRpcError(JsonRpcError {
                code: 3,
                data: Some(json!(encode(&data))),
                message: "execution reverted".to_string(),
            }))
            .await
            .expect("failed to get error selector");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name: "UnexpectedOperandValue".to_owned(),
                args: vec![],
                sig: "UnexpectedOperandValue()".to_owned(),
                data
            },
            res
        );
    }

    #[tokio::test]
    async fn test_error_decoder_provider_error_no_data() {
        let res =
            AbiDecodedErrorType::try_from_provider_error(MockError::JsonRpcError(JsonRpcError {
                code: 3,
                data: None,
                message: "execution reverted".to_string(),
            }))
            .await
            .expect("failed to get error selector");
        assert_eq!(AbiDecodedErrorType::Unknown(vec![]), res);
    }

    #[tokio::test]
    async fn test_error_decoder_provider_error_no_data_str() {
        let res =
            AbiDecodedErrorType::try_from_provider_error(MockError::JsonRpcError(JsonRpcError {
                code: 3,
                data: Some(json!(42)),
                message: "execution reverted".to_string(),
            }))
            .await
            .expect("failed to get error selector");
        assert_eq!(AbiDecodedErrorType::Unknown(vec![]), res);
    }

    #[tokio::test]
    async fn test_error_decoder_provider_error_no_data_str_invalid() {
        let res =
            AbiDecodedErrorType::try_from_provider_error(MockError::JsonRpcError(JsonRpcError {
                code: 3,
                data: Some(json!("invalid")),
                message: "execution reverted".to_string(),
            }))
            .await;

        let err = res.expect_err("expected error");

        match err {
            AbiDecodeFailedErrors::HexDecodeError(_) => {}
            _ => panic!("unexpected error"),
        }
    }

    #[tokio::test]
    async fn test_decode_panic_error_known_reason() {
        let arg_data = U256::from(0x12);
        let res = AbiDecodedErrorType::decode_panic(PANIC_SELECTOR, &arg_data.to_be_bytes_vec())
            .expect("expected to be some");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name:
                    "Panic, reason: divide or modulo by zero (e.g. 5 / 0 or 23 % 0), (code: 0x12)"
                        .to_string(),
                args: vec![format!("{:?}", arg_data)],
                sig: PANIC_SIG.to_string(),
                data: arg_data.to_be_bytes_vec(),
            },
            res
        );
    }

    #[tokio::test]
    async fn test_decode_panic_error_unknown_reason() {
        let arg_data = U256::from(0x777);
        let res = AbiDecodedErrorType::decode_panic(PANIC_SELECTOR, &arg_data.to_be_bytes_vec())
            .expect("expected to be some");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name: "Panic, reason: unknown, (code: 0x0777)".to_string(),
                args: vec![format!("{:?}", arg_data)],
                sig: PANIC_SIG.to_string(),
                data: arg_data.to_be_bytes_vec(),
            },
            res
        );
    }

    #[tokio::test]
    async fn test_error_decoder_provider_with_panic() {
        let arg_data = U256::from(0x51);
        let mut data = PANIC_SELECTOR.to_vec();
        data.extend_from_slice(&arg_data.to_be_bytes_vec());

        let res =
            AbiDecodedErrorType::try_from_provider_error(MockError::JsonRpcError(JsonRpcError {
                code: 3,
                data: Some(json!(encode(&data))),
                message: "execution reverted".to_string(),
            }))
            .await
            .expect("failed to get error selector");
        assert_eq!(
            AbiDecodedErrorType::Known {
                name: "Panic, reason: called a zero-initialized variable of internal function type, (code: 0x51)".to_string(),
                args: vec![format!("{:?}", arg_data)],
                sig: PANIC_SIG.to_string(),
                data: arg_data.to_be_bytes_vec(),
            },
            res
        );
    }
}
