// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! <!-- markdown-link-check-disable -->
//! # Offchain Worker Example Pallet
//!
//! The Offchain Worker Example: A simple pallet demonstrating
//! concepts, APIs and structures common to most offchain workers.
//!
//! Run `cargo doc --package pallet-example-offchain-worker --open` to view this module's
//! documentation.
//!
//! - [`Config`]
//! - [`Call`]
//! - [`Pallet`]
//!
//! **This pallet serves as an example showcasing Substrate off-chain worker and is not meant to
//! be used in production.**
//!
//! ## Overview
//!
//! In this example we are going to build a very simplistic, naive and definitely NOT
//! production-ready oracle for BTC/USD price.
//! Offchain Worker (OCW) will be triggered after every block, fetch the current price
//! and prepare either signed or unsigned transaction to feed the result back on chain.
//! The on-chain logic will simply aggregate the results and store last `64` values to compute
//! the average price.
//! Additional logic in OCW is put in place to prevent spamming the network with both signed
//! and unsigned transactions, and custom `UnsignedValidator` makes sure that there is only
//! one unsigned transaction floating in the network.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use codec::{Decode, Encode};
use frame_support::BoundedVec;
use frame_support::traits::Get;
use frame_system::{
	self as system,
	offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
		SignedPayload, Signer, SigningTypes, SubmitTransaction,
	},
	pallet_prelude::BlockNumberFor,
};
use lite_json::json::JsonValue;
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
	offchain::{
		http,
		storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
		Duration,
		StorageKind,
	},
	traits::Zero,
	transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
	RuntimeDebug,
};
use sp_io::offchain;

use sp_std::vec::Vec;
use sp_std::vec;

use serde::Deserialize;
use serde_json::Value;
use scale_info::prelude::string::String;

#[cfg(test)]
mod tests;

/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"btc!");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

pub use pallet::*;

#[derive(Deserialize, Debug)]
struct ResponseData {
	epoch: EpochData,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EpochData {
	reference_gas_price: String,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// This pallet's configuration trait
	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		// Configuration parameters

		/// A grace period after we send transaction.
		///
		/// To avoid sending too many transactions, we only attempt to send one
		/// every `GRACE_PERIOD` blocks. We use Local Storage to coordinate
		/// sending between distinct runs of this offchain worker.
		#[pallet::constant]
		type GracePeriod: Get<BlockNumberFor<Self>>;

		/// Number of blocks of cooldown after unsigned transaction is included.
		///
		/// This ensures that we only accept unsigned transactions once, every `UnsignedInterval`
		/// blocks.
		#[pallet::constant]
		type UnsignedInterval: Get<BlockNumberFor<Self>>;

		/// A configuration for base priority of unsigned transactions.
		///
		/// This is exposed so that it can be tuned for particular runtime, when
		/// multiple pallets send unsigned transactions.
		#[pallet::constant]
		type UnsignedPriority: Get<TransactionPriority>;


		/// Maximum size of a task.
		#[pallet::constant]
		type MaxTaskSize: Get<u32>;

		/// Maximum number of tasks.
		#[pallet::constant]
		type MaxTasks: Get<u32>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);


	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		/// Offchain Worker entry point.
		///
		/// By implementing `fn offchain_worker` you declare a new offchain worker.
		/// This function will be called when the node is fully synced and a new best block is
		/// successfully imported.
		/// Note that it's not guaranteed for offchain workers to run on EVERY block, there might
		/// be cases where some blocks are skipped, or for some the worker runs twice (re-orgs),
		/// so the code should be able to handle that.
		/// You can use `Local Storage` API to coordinate runs of the worker.
		fn offchain_worker(block_number: BlockNumberFor<T>) {
			log::info!("离线工作者在区块开始: {:?}", block_number);

			let tasks = Self::tasks();
			if !tasks.is_empty() {	
				log::info!("有任务: {:?}", tasks);
				for (index, task) in tasks.iter().enumerate() {
					log::info!("处理任务: {:?}", task);
					if let Err(e) = Self::process_task(block_number, index as u32, task) {
						log::error!("处理任务时出错: {:?}", e);
					}
				}
				log::info!("所有任务已处理");
			}
		}
	}

	/// A public part of the pallet.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn submit_task(origin: OriginFor<T>, task: BoundedVec<u8, T::MaxTaskSize>) -> DispatchResult {
			ensure_signed(origin)?;

			Tasks::<T>::try_mutate(|tasks| {
				tasks.try_push(task.clone())
					.map_err(|_| Error::<T>::TooManyTasks)
			})?;
			
			Self::deposit_event(Event::TaskSubmitted{task: task.to_vec()});
			Ok(())
        }

		#[pallet::call_index(1)]
		#[pallet::weight({0})]
		pub fn process_task_unsigned(
			origin: OriginFor<T>,
			block_number: BlockNumberFor<T>,
			task_index: u32
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			Self::remove_task(task_index);
			let current_block = <system::Pallet<T>>::block_number();
			<NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
			Ok(().into())
		}

		// #[pallet::call_index(1)]
		// #[pallet::weight({0})]
		// pub fn process_task(origin: OriginFor<T>, task: BoundedVec<u8, T::MaxTaskSize>) -> DispatchResult {
		// 	ensure_signed(origin)?;
		// 	Self::process_task(&task);
		// 	Ok(())
		// }
	}

	/// Events for the pallet.
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        TaskSubmitted{task: Vec<u8>},
        TaskProcessed{task: Vec<u8>},
	}



	#[pallet::error]
	pub enum Error<T> {
		TooManyTasks,
	}


	#[pallet::validate_unsigned]
impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
        if let Call::process_task_unsigned { block_number, task_index } = call {
            // 检查是否到了可以提交新的未签名交易的时间
            let current_block = <system::Pallet<T>>::block_number();
            let next_unsigned_at = <NextUnsignedAt<T>>::get();
            if current_block < next_unsigned_at {
                return InvalidTransaction::Stale.into();
            }

            // 检查任务是否存在
            let tasks = Self::tasks();
            if (*task_index as usize) >= tasks.len() {
                return InvalidTransaction::Custom(1).into(); // 任务不存在
            }

            ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
                .priority(T::UnsignedPriority::get())
                .and_provides((*block_number, *task_index))
                .longevity(5)
                .propagate(true)
                .build()
        } else {
            InvalidTransaction::Call.into()
        }
    }
}

	#[pallet::storage]
	#[pallet::getter(fn tasks)]
	pub type Tasks<T: Config> = StorageValue<_, BoundedVec<BoundedVec<u8, T::MaxTaskSize>, T::MaxTasks>, ValueQuery>;

	#[pallet::storage]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;
}

/// Payload used by this example crate to hold price
/// data required to submit a transaction.
#[derive(Encode, Decode, Clone, PartialEq, Eq, RuntimeDebug, scale_info::TypeInfo)]
pub struct PricePayload<Public, BlockNumber> {
	block_number: BlockNumber,
	price: u32,
	public: Public,
}

impl<T: SigningTypes> SignedPayload<T> for PricePayload<T::Public, BlockNumberFor<T>> {
	fn public(&self) -> T::Public {
		self.public.clone()
	}
}

impl<T: Config> Pallet<T> {
    fn process_task(
		block_number: BlockNumberFor<T>,
		task_index: u32, 
		task: &[u8]
	) -> Result<(), &'static str> {
        log::info!("处理任务: {:?}", task);
        
        match Self::test_sui() {
            Ok(gas_price) => {
                log::info!("Sui gas 价格: {:?}", gas_price);
                Self::deposit_event(Event::TaskProcessed{task: task.to_vec()});
                
                let call = Call::process_task_unsigned { block_number, task_index };

                SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
                    .map_err(|()| "无法提交未签名交易。")?;
                Ok(())
            },
            Err(e) => {
                log::error!("获取 Sui gas 价格时出错: {:?}", e);
                Err("获取 Sui gas 价格失败")
            }
        }
    }

    fn remove_task(task_index: u32) {
        Tasks::<T>::mutate(|tasks| {
            if (task_index as usize) < tasks.len() {
                tasks.remove(task_index as usize);
            }
        });
    }

	fn test_sui() -> Result<u32, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		// Initiate an external HTTP GET request.
		// This is using high-level wrappers from `sp_runtime`, for the low-level calls that
		// you can find in `sp_io`. The API is trying to be similar to `request`, but
		// since we are running in a custom WASM execution environment we can't simply
		// import the library here.
		let request =
			http::Request::get("https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD");
		// We set the deadline for sending of the request, note that awaiting response can
		// have a separate deadline. Next we send the request, before that it's also possible
		// to alter request headers or stream body content in case of non-GET requests.
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;

		// The request is already being processed by the host, we are free to do anything
		// else in the worker (we can send multiple concurrent requests too).
		// At some point however we probably want to check the response though,
		// so we can block current thread and wait for it to finish.
		// Note that since the request is being driven by the host, we don't have to wait
		// for the request to have it complete, we will just not read the response.
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		// Let's check the status code before we proceed to reading the response.
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}

		// Next we want to fully read the response body and collect it to a vector of bytes.
		// Note that the return object allows you to read the body in chunks as well
		// with a way to control the deadline.
		let body = response.body().collect::<Vec<u8>>();

		// Create a str slice from the body.
		let body_str = alloc::str::from_utf8(&body).map_err(|_| {
			log::warn!("No UTF8 body");
			http::Error::Unknown
		})?;

		let price = match Self::parse_price(body_str) {
			Some(price) => Ok(price),
			None => {
				log::warn!("Unable to extract price from the response: {:?}", body_str);
				Err(http::Error::Unknown)
			},
		}?;

		log::warn!("Got price: {} cents", price);

		Ok(price)

		// let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000)); // 增加到 10 秒
		// // let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(5_000)); // 增加到 5 秒
		// let url = "https://graphql-beta.mainnet.sui.io";
		// let request_body = r#"{"query": "query { epoch { referenceGasPrice } }"}"#;
		// log::info!("Preparing to send request to {}", url);
		// let request = http::Request::post(url, vec![request_body.clone()])
		// .add_header("Content-Type", "application/json");
		// let pending = request
		// .deadline(deadline)
		// .send()
		// .map_err(|e| {
		// 	log::debug!("发送请求失败: {:?}", e);
		// 	http::Error::IoError
		// })?;
		// log::info!("Request sent, waiting for response");
		// let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		// log::info!("Response received with status code: {}", response.code);
		// if response.code != 200 {
		// 	log::debug!("Unexpected status code: {}", response.code);
		// 	return Err(http::Error::Unknown)
		// }

		// let body = response.body().collect::<Vec<u8>>();
		// log::info!("5");
		// let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
		// 	log::warn!("No UTF8 body");
		// 	http::Error::Unknown
		// })?;
		// let response_json: Value = serde_json::from_str(body_str).map_err(|err| {
		// 	log::warn!("Error parsing response body as JSON 1 : {}", err);
		// 	http::Error::Unknown
		// })?;
		// let response_data: ResponseData = serde_json::from_value(response_json["data"].clone()).map_err(|err| {
		// 	log::warn!("Error parsing response body as JSON 2: {}", err);
		// 	http::Error::Unknown
		// })?;
		// log::info!("Info from Sui response_data: {:?}",response_data);
		// log::info!("8");
		// let reference_gas_price = response_data.epoch.reference_gas_price;
		// log::info!("Info from Sui reference_gas_price: {:?}",reference_gas_price);
		// log::info!("9");
		// // let reference_gas_price:&str = match response_data.epoch.referenceGasPrice {
		// // 	Some(reference_gas_price) => Ok(reference_gas_price),
		// // 	None => {
		// // 		log::warn!("Unable to extract price from the response: {:?}", body_str);
		// // 		Err(http::Error::Unknown)
		// // 	},
		// // }?;

		// log::info!("Info from Sui: {:?}",reference_gas_price);
		// log::info!("Current Gas price: {:?}",reference_gas_price);
		// Ok(reference_gas_price)
		// // Ok(())
	}
		/// Parse the price from the given JSON string using `lite-json`.
	///
	/// Returns `None` when parsing failed or `Some(price in cents)` when parsing is successful.
	fn parse_price(price_str: &str) -> Option<u32> {
		let val = lite_json::parse_json(price_str);
		let price = match val.ok()? {
			JsonValue::Object(obj) => {
				let (_, v) = obj.into_iter().find(|(k, _)| k.iter().copied().eq("USD".chars()))?;
				match v {
					JsonValue::Number(number) => number,
					_ => return None,
				}
			},
			_ => return None,
		};

		let exp = price.fraction_length.saturating_sub(2);
		Some(price.integer as u32 * 100 + (price.fraction / 10_u64.pow(exp)) as u32)
	}
}
