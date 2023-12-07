//! # Verifiable PoC Pallet

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

// I know... we should not do this. But this is handy for testing
extern crate alloc;
use alloc::string::String;

use ark_scale::{ark_serialize::CanonicalDeserialize, ArkScale};
use frame_support::BoundedVec;
use sp_std::vec::Vec;
use verifiable::{
	ring_vrf_impl::{
		bandersnatch_vrfs::ring::StaticVerifierKey, BandersnatchVrfVerifiable as RingVrfVerifiable,
		DOMAIN_SIZE,
	},
	GenerateVerifiable,
};

const LOG_TARGET: &str = "verifiable 🛡";

const SRS_MAX_CHUNKS: u32 = DOMAIN_SIZE as u32;

#[cfg(feature = "small-ring")]
const ONCHAIN_VK: &'static [u8] = include_bytes!("zcash-9.vk");
#[cfg(not(feature = "small-ring"))]
const ONCHAIN_VK: &'static [u8] = include_bytes!("zcash-16.vk");

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	type SrsChunksVec = BoundedVec<
		<RingVrfVerifiable as GenerateVerifiable>::StaticChunk,
		ConstU32<SRS_MAX_CHUNKS>,
	>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::error]
	pub enum Error<T> {
		RingNotInitialized,
		RingNotFinalized,
		PushMemberFailure,
		RingFinalized,
		ValidationFailure,
	}

	#[pallet::storage]
	type Intermediate<T> = StorageValue<_, <RingVrfVerifiable as GenerateVerifiable>::Intermediate>;

	#[pallet::storage]
	type SrsChunks<T> = StorageValue<_, SrsChunksVec, ValueQuery>;

	#[pallet::storage]
	type Members<T> = StorageValue<_, <RingVrfVerifiable as GenerateVerifiable>::Members>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		#[serde(skip)]
		pub _phantom: sp_std::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			let vk = StaticVerifierKey::deserialize_uncompressed_unchecked(ONCHAIN_VK)
				.expect("Failed to deserialize onchain vk");
			assert_eq!(vk.lag_g1.len(), DOMAIN_SIZE);

			log::debug!(target: LOG_TARGET, "Building SRS chunks for domain size: {}", vk.lag_g1.len());
			let srs_chunks: Vec<_> = vk.lag_g1.into_iter().map(|p| ArkScale(p)).collect();
			SrsChunks::<T>::set(SrsChunksVec::truncate_from(srs_chunks));

			// Init empty ring
			Pallet::<T>::make_empty_ring();

			log::debug!(target: LOG_TARGET, "Initialization completed");
		}
	}

	/// Push a new ring member.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(Weight::zero())]
		pub fn push_member(
			origin: OriginFor<T>,
			member: <RingVrfVerifiable as GenerateVerifiable>::Member,
		) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			if Members::<T>::exists() {
				log::warn!(target: LOG_TARGET, "Ring membership finalized");
				return Err(Error::<T>::RingFinalized.into())
			}

			let Some(mut intermediate) = Intermediate::<T>::get() else {
				log::warn!(target: LOG_TARGET, "Ring not initialized");
				return Err(Error::<T>::RingNotInitialized.into())
			};

			// NOTE: this should not be fully loaded. Just load the single chunk
			// in the `get_chunk` closure.
			let srs_chunks = SrsChunks::<T>::get();
			let get_chunk = |i: usize| {
				log::debug!(target: LOG_TARGET, "Adding member to index: {}", i);
				Ok(srs_chunks[i].clone())
			};

			RingVrfVerifiable::push_member(&mut intermediate, member, get_chunk)
				.map_err(|_| Error::<T>::PushMemberFailure)?;
			log::debug!(target: LOG_TARGET, "Done");

			Intermediate::<T>::set(Some(intermediate));

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(Weight::zero())]
		pub fn finish_members(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			let Some(intermediate) = Intermediate::<T>::get() else {
				log::warn!(target: LOG_TARGET, "Ring not initialized");
				return Err(Error::<T>::RingNotInitialized.into())
			};

			log::debug!(target: LOG_TARGET, "Finalizing ring (members = {})", intermediate.ring.curr_keys);

			let members = RingVrfVerifiable::finish_members(intermediate);
			Members::<T>::set(Some(members));

			log::debug!(target: LOG_TARGET, "Done");

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(Weight::zero())]
		pub fn reset_members(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			Members::<T>::kill();
			Self::make_empty_ring();

			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(Weight::zero())]
		pub fn validate_proof(
			origin: OriginFor<T>,
			proof: <RingVrfVerifiable as GenerateVerifiable>::Proof,
			message: String,
		) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			log::debug!(target: LOG_TARGET, "Validating proof: {}", hex::encode(proof));
			log::debug!(target: LOG_TARGET, "For message: {}", message);

			let Some(members) = Members::<T>::get() else {
				log::error!(target: LOG_TARGET, "Ring not finalized");
				return Err(Error::<T>::RingNotFinalized.into())
			};

			let Ok(alias) =
				RingVrfVerifiable::validate(&proof, &members, b"VERIFIABLE", message.as_bytes())
			else {
				log::error!(target: LOG_TARGET, "Validation failure");
				return Err(Error::<T>::ValidationFailure.into())
			};

			log::debug!(target: LOG_TARGET, "Validated alias: {}", hex::encode(alias));

			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn make_empty_ring() {
			log::debug!(target: LOG_TARGET, "Initialize empty ring");
			let intermediate = RingVrfVerifiable::start_members();
			Intermediate::<T>::set(Some(intermediate));
		}
	}
}
