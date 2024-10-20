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

use alloc::format;
use codec::{Decode, Encode};
use frame_support::{
	pallet_prelude::{BoundedVec, MaxEncodedLen},
	traits::Get,
};
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
use scale_info::TypeInfo;
use sp_std::fmt::Debug;

#[cfg(test)]
mod tests;

#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, Default, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(StringLimit))]
pub struct Task<StringLimit: Get<u32> + Clone> {
	pub da_height: u64,
	pub blob: BoundedVec<u8, StringLimit>,
	pub processed: bool,
}

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
#[serde(rename_all = "camelCase")]
struct ResponseData {
    is_succ: bool,
    #[serde(default)]
    res: Option<TimeData>,
    #[serde(default)]
    err: Option<ErrorData>,
}

#[derive(Deserialize, Debug)]
struct TimeData {
    time: String,
}

#[derive(Deserialize, Debug)]
struct ErrorData {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: String,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use super::Task;

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
		type StringLimit: Get<u32> + Clone;

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
			log::info!("Offchain worker started at block: {:?}", block_number);

			let tasks = Self::tasks();
			if !tasks.is_empty() {	
				log::info!("Number of tasks: {:?}", tasks.len());
				for (index, task) in tasks.iter().enumerate() {
					if !task.processed {
						log::info!("Processing task: {:?}", task.blob.clone());
						if let Err(e) = Self::process_task(block_number, index as u32, task) {
							log::error!("Error processing task: {:?}", e);
						}
					}
				}
				log::info!("All tasks processed");
			}
		}
	}

	/// A public part of the pallet.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight({0})]
		pub fn submit_task(origin: OriginFor<T>, da_height: u64, blob: Vec<u8>) -> DispatchResult {
			ensure_signed(origin)?;

			let last_height = Self::last_da_height();
			ensure!(da_height > last_height, Error::<T>::InvalidDaHeight);

			let bounded_blob: BoundedVec<u8, T::StringLimit> =
			blob.clone().try_into().map_err(|_| Error::<T>::BlobTooLong)?;

			let new_task = super::Task {
				da_height,
				blob: bounded_blob.clone(),
				processed: false,
			};

			Tasks::<T>::try_mutate(|tasks| {
				tasks.try_push(new_task.clone())
					.map_err(|_| Error::<T>::TooManyTasks)
			})?;

			TaskHistory::<T>::insert(da_height, (bounded_blob, false));
			
			// 更新最后提交的 da_height
			LastDaHeight::<T>::put(da_height);

			Self::deposit_event(Event::TaskSubmitted { da_height: new_task.da_height, blob: new_task.blob });
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight({0})]
		pub fn process_task_unsigned(
			origin: OriginFor<T>,
			block_number: BlockNumberFor<T>,
			task_index: u32,
		) -> DispatchResultWithPostInfo {
			ensure_none(origin)?;
			Self::remove_task(task_index);
			let current_block = <system::Pallet<T>>::block_number();

			<NextUnsignedAt<T>>::put(current_block + T::UnsignedInterval::get());
			Ok(().into())
		}
	}

	/// Events for the pallet.
	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        TaskSubmitted{da_height: u64, blob: BoundedVec<u8, T::StringLimit>},
        TaskProcessed{da_height: u64, blob: BoundedVec<u8, T::StringLimit>},
	}

	#[pallet::error]
	pub enum Error<T> {
		TooManyTasks,
		DaHeightTooLong,
		BlobTooLong,
		InvalidDaHeight,
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			if let Call::process_task_unsigned { block_number, task_index } = call {
				// Check if it's time to submit a new unsigned transaction
				let current_block = <system::Pallet<T>>::block_number();
				let next_unsigned_at = <NextUnsignedAt<T>>::get();
				if current_block < next_unsigned_at {
					return InvalidTransaction::Stale.into();
				}

				// Check if the task exists
				let tasks = Self::tasks();
				if (*task_index as usize) >= tasks.len() {
					return InvalidTransaction::Custom(1).into(); // Task doesn't exist
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
	pub type Tasks<T: Config> = StorageValue<_, BoundedVec<Task<T::StringLimit>, T::MaxTasks>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn task_by_height)]
	pub type TaskHistory<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		u64,  // da_height as key
		(BoundedVec<u8, T::StringLimit>, bool),  // (blob, processed) as value
		ValueQuery
	>;

	#[pallet::storage]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn last_da_height)]
	pub type LastDaHeight<T: Config> = StorageValue<_, u64, ValueQuery>;
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
		task: &Task<T::StringLimit>
	) -> Result<(), &'static str> {
        log::info!("Processing task: {:?}", task.blob.clone());
        
        match Self::test_sui(task.da_height, task.blob.clone()) {
            Ok(gas_price) => {
                log::info!("Sui gas price: {:?}", gas_price);
                
                // Update task status
                Tasks::<T>::mutate(|tasks| {
                    if let Some(task) = tasks.get_mut(task_index as usize) {
                        task.processed = true;
                    }
                });

                Self::deposit_event(Event::TaskProcessed { da_height: task.da_height, blob: task.blob.clone() });
                
                let call = Call::process_task_unsigned { block_number, task_index };

                SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
                    .map_err(|()| "Unable to submit unsigned transaction")?;
                Ok(())
            },
            Err(e) => {
                log::error!("Error getting Sui gas price: {:?}", e);
                Err("Failed to get Sui gas price")
            }
        }
    }

    fn remove_task(task_index: u32) {
        let mut da_height = None;
        Tasks::<T>::mutate(|tasks| {
            if (task_index as usize) < tasks.len() {
                if let Some(task) = tasks.get(task_index as usize) {
                    da_height = Some(task.da_height);
                }
                tasks.remove(task_index as usize);
            }
        });

        if let Some(height) = da_height {
            // Update processing status
            TaskHistory::<T>::mutate(height, |task| {
                let (blob, _) = task;
                *task = (blob.clone(), true);
            });
        }
    }

	fn fetch_price() -> Result<u32, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let request =
			http::Request::get("https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD");
		let pending = request.deadline(deadline).send().map_err(|_| http::Error::IoError)?;
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		if response.code != 200 {
			log::warn!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown)
		}

		let body = response.body().collect::<Vec<u8>>();
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
	}

	fn test_sui(da_height: u64, blob: BoundedVec<u8, T::StringLimit>) -> Result<u32, http::Error> {
		let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
		let url = "http://47.236.78.251:3000/v1/Warlus/Store";
		
		let blob_str = sp_std::str::from_utf8(&blob).map_err(|_| {
			log::error!("Unable to convert blob to string");
			http::Error::Unknown
		})?;
		
		let request_body = format!(
			r#"{{"da_height": {}, "blob": "{}", "epochs": 1}}"#,
			da_height, blob_str
		);
		
		log::info!("Preparing to send request to {}", url);
		log::info!("Request body: {}", request_body);
		let request = http::Request::post(url, vec![request_body])
			.add_header("Content-Type", "application/json");
		
		let pending = request
			.deadline(deadline)
			.send()
			.map_err(|e| {
				log::error!("Failed to send request: {:?}", e);
				http::Error::IoError
			})?;
		
		log::info!("Request sent, waiting for response");
		let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
		log::info!("Response received, status code: {}", response.code);
		
		if response.code != 200 {
			log::error!("Unexpected status code: {}", response.code);
			return Err(http::Error::Unknown);
		}
	
		let body = response.body().collect::<Vec<u8>>();
		let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
			log::error!("Response body is not valid UTF-8");
			http::Error::Unknown
		})?;
	
		log::info!("Received response body: {}", body_str);
	
		let response_json: ResponseData = serde_json::from_str(body_str).map_err(|err| {
			log::error!("Failed to parse JSON response: {}", err);
			http::Error::Unknown
		})?;
	
		log::info!("Parsed JSON: {:?}", response_json);
	
		if !response_json.is_succ {
			if let Some(err) = response_json.err {
				log::error!("Error from server: {:?}", err);
			}
			return Err(http::Error::Unknown);
		}

		let time = response_json.res.ok_or_else(|| {
			log::error!("Missing 'res' field in successful response");
			http::Error::Unknown
		})?.time;

		log::info!("Time retrieved from Sui: {}", time);
	
		Ok(1u32) // Return a fixed value, you can modify this based on your actual requirements
	}
		
	/// Parse the price from the given JSON string using `lite-json`.
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

