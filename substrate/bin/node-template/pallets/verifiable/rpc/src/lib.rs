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

//! RPC interface for verifiable pallet PoC

// use codec::{Codec, Decode};
use jsonrpsee::{
	core::{Error as JsonRpseeError, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorCode, ErrorObject},
};
use std::{
	collections::{hash_map::Entry, HashMap},
	sync::Mutex,
};
use verifiable::{
	ring_vrf_impl::{bandersnatch_vrfs::CanonicalDeserialize, RingVrfVerifiable},
	GenerateVerifiable,
};

const LOG_TARGET: &str = "verifiable:rpc";

#[rpc(client, server)]
pub trait VerifiableApi {
	#[method(name = "verifiable_keygen")]
	fn keygen(&self, phrase: &str) -> RpcResult<String>;

	#[method(name = "verifiable_open")]
	fn open(&self, member: String) -> RpcResult<()>;
}

type Seed = [u8; 32];
type RawMember = [u8; 33];

struct MemberData {
	seed: Seed,
	commitment: Option<<RingVrfVerifiable as GenerateVerifiable>::Commitment>,
}

pub struct Verifiable {
	keymap: Mutex<HashMap<RawMember, MemberData>>,
}

impl Verifiable {
	pub fn new() -> Self {
		Self { keymap: Mutex::new(HashMap::new()) }
	}
}

pub enum Error {
	DecodeError,
	EncodeError,
}

fn my_err(e: Error, msg: String) -> CallError {
	CallError::Custom(ErrorObject::owned(e as i32, msg, None::<()>))
}

impl VerifiableApiServer for Verifiable {
	fn keygen(&self, phrase: &str) -> RpcResult<String> {
		use verifiable::ring_vrf_impl::bandersnatch_vrfs::CanonicalSerialize;

		log::debug!(target: LOG_TARGET, "Generating new verifiable key");
		log::debug!(target: LOG_TARGET, "  phrase: {}", phrase);
		let seed = sp_core::hashing::blake2_256(phrase.as_bytes());
		let secret = RingVrfVerifiable::new_secret(seed);
		let member = RingVrfVerifiable::member_from_secret(&secret);

		// Since we are currently using a patched version of `ark-scale`, the `ArkScale`
		// returned by `member_from_secret` is not compatible with the one used here.
		// So we use this temporary trick and we serialize directly using ark-serialize.
		let mut raw_public = [0u8; 33];
		member
			.0
			.serialize_compressed(raw_public.as_mut_slice())
			.map_err(|e| my_err(Error::EncodeError, e.to_string()))?;

		let member = hex::encode(raw_public).to_string();
		log::debug!(target: LOG_TARGET, "  member: 0x{}", member);

		let mut keymap = self.keymap.lock().unwrap();
		keymap.insert(raw_public, MemberData { seed, commitment: None });

		log::debug!(target: LOG_TARGET, "  members count: {}", keymap.len());

		Ok(member)
	}

	// This should be called when we know the entire ring
	fn open(&self, member: String) -> RpcResult<()> {
		use verifiable::ring_vrf_impl::bandersnatch_vrfs::PublicKey;

		let mut keymap = self.keymap.lock().unwrap();
		let members: Vec<_> = keymap
			.keys()
			.map(|m| {
				let buf = *m;
				let pk = PublicKey::deserialize_compressed(buf.as_slice())
					.expect("Deserializing members");
				pk.into()
			})
			.collect();

		let raw_member = hex::decode(member).map_err(|e| {
			log::error!(target: LOG_TARGET, "Error decoding input element (bad hex)");
			my_err(
				Error::DecodeError,
				format!("Decoding input element (bad hex): {}", e.to_string()),
			)
		})?;

		let member = PublicKey::deserialize_compressed(raw_member.as_slice()).map_err(|e| {
			log::error!(target: LOG_TARGET, "Error decoding input element");
			my_err(Error::DecodeError, format!("Decoding input element: {}", e.to_string()))
		})?;

		// Now we can safery assume 33 bytes
		let mut map_key = [0u8; 33];
		map_key.copy_from_slice(raw_member.as_slice());
		let Entry::Occupied(mut member_entry) = keymap.entry(map_key) else {
			log::error!(target: LOG_TARGET, "Member not found");
			return Err(my_err(Error::DecodeError, "Member no found".into()).into())
		};

		let commitment =
			RingVrfVerifiable::open(&member.into(), members.into_iter()).map_err(|_| {
				log::error!(target: LOG_TARGET, "Error generating commitment");
				my_err(Error::DecodeError, "Generating commitment".to_string())
			})?;

		member_entry.get_mut().commitment = Some(commitment);

		log::debug!(target: LOG_TARGET, "Member commitment persisted");

		Ok(())
	}
}
