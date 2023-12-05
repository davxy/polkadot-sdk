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
	core::RpcResult,
	proc_macros::rpc,
	types::error::{CallError, ErrorObject},
};
use std::{
	collections::{hash_map::Entry, HashMap},
	sync::Mutex,
};
use verifiable::{
	ring_vrf_impl::{bandersnatch_vrfs::CanonicalDeserialize, RingVrfVerifiable},
	GenerateVerifiable,
};

const LOG_TARGET: &str = "verifiable:rpc 🛡";

#[rpc(client, server)]
pub trait VerifiableApi {
	#[method(name = "verifiable_keygen")]
	fn keygen(&self, phrase: &str) -> RpcResult<String>;

	#[method(name = "verifiable_open")]
	fn open(&self, member: String) -> RpcResult<()>;

	#[method(name = "verifiable_create")]
	fn create(&self, member: String, message: String) -> RpcResult<(String, String)>;
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
	Decode,
	Encode,
	MemberNotFound,
	CommitNotFound,
	Commitment,
	Proof,
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
			.map_err(|e| my_err(Error::Encode, e.to_string()))?;

		let member = hex::encode(raw_public).to_string();
		log::debug!(target: LOG_TARGET, "  member: 0x{}", member);

		let mut keymap = self.keymap.lock().unwrap();
		keymap.insert(raw_public, MemberData { seed, commitment: None });

		log::debug!(target: LOG_TARGET, "  members count: {}", keymap.len());

		Ok(member)
	}

	// This should be called when the ring is finalized
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

		let raw_member =
			to_raw_member(member).map_err(|e| my_err(e, format!("Decoding input member")))?;

		let member = PublicKey::deserialize_compressed(raw_member.as_slice()).map_err(|e| {
			log::error!(target: LOG_TARGET, "Error decoding input element");
			my_err(Error::Decode, format!("Decoding input element: {}", e.to_string()))
		})?;

		let Entry::Occupied(mut member_entry) = keymap.entry(raw_member) else {
			log::error!(target: LOG_TARGET, "Member not found");
			return Err(my_err(Error::MemberNotFound, "Member no found".into()).into())
		};

		let commitment =
			RingVrfVerifiable::open(&member.into(), members.into_iter()).map_err(|_| {
				log::error!(target: LOG_TARGET, "Error generating commitment");
				my_err(Error::Commitment, "Generating commitment".to_string())
			})?;

		member_entry.get_mut().commitment = Some(commitment);

		log::debug!(target: LOG_TARGET, "Member commitment persisted");

		Ok(())
	}

	fn create(&self, member: String, message: String) -> RpcResult<(String, String)> {
		let mut keymap = self.keymap.lock().unwrap();

		let raw_member =
			to_raw_member(member).map_err(|e| my_err(e, format!("Decoding input member")))?;

		let Entry::Occupied(mut member_entry) = keymap.entry(raw_member) else {
			log::error!(target: LOG_TARGET, "Member not found");
			return Err(my_err(Error::MemberNotFound, "Member no found".into()).into())
		};

		let Some(commitment) = member_entry.get_mut().commitment.take() else {
			log::error!(target: LOG_TARGET, "Member commitment not found");
			return Err(my_err(Error::CommitNotFound, "Member commitment no found".into()).into())
		};

		let seed = member_entry.get().seed;
		let secret = RingVrfVerifiable::new_secret(seed);
		// TODO : check if public is equal to member

		let (proof, alias) =
			RingVrfVerifiable::create(commitment, &secret, b"VERIFIABLE", message.as_bytes())
				.map_err(|_| {
					log::error!(target: LOG_TARGET, "Error generating proof");
					my_err(Error::Proof, "Generating proof".to_string())
				})?;

		let alias = hex::encode(alias);
		let proof = hex::encode(proof);
		log::debug!(target: LOG_TARGET, "Proof: {}", proof);
		log::debug!(target: LOG_TARGET, "Alias: {}", alias);

		Ok((alias, proof))
	}
}

fn to_raw_member(member: String) -> Result<RawMember, Error> {
	let bytes = hex::decode(member).map_err(|_| {
		log::error!(target: LOG_TARGET, "Error decoding member (bad hex)");
		Error::Decode
	})?;

	if bytes.len() != 33 {
		log::error!(target: LOG_TARGET, "Error decoding member element (bad length)");
		return Err(Error::Decode)
	}

	let mut raw_member = [0u8; 33];
	raw_member.copy_from_slice(bytes.as_slice());
	Ok(raw_member)
}
