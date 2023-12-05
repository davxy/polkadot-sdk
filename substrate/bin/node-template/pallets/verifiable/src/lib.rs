//! # Verifiable PoC Pallet

// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

// Re-export pallet items so that they can be accessed from the crate namespace.
pub use pallet::*;

use ark_scale::ArkScale;
use frame_support::BoundedVec;
use sp_std::vec::Vec;
use verifiable::{
	ring_vrf_impl::{
		bandersnatch_vrfs::{bls12_381::G1Affine, ring::KZG},
		fflonk::pcs::PcsParams,
		ring::ring::RingBuilderKey,
		BandersnatchVrfVerifiable,
	},
	GenerateVerifiable,
};

const LOG_TARGET: &str = "verifiable";

const DOMAIN_SIZE: usize = 1 << 9;

const SRS_MAX_CHUNKS: u32 = DOMAIN_SIZE as u32;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	type SrsChunksVec = BoundedVec<ArkScale<G1Affine>, ConstU32<SRS_MAX_CHUNKS>>;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type DomainSize: Get<u32>;
	}

	#[pallet::error]
	pub enum Error<T> {
		RingNotInitialized,
		PushMemberFailure,
		RingFinalized,
	}

	#[pallet::storage]
	type Intermediate<T> =
		StorageValue<_, <BandersnatchVrfVerifiable as GenerateVerifiable>::Intermediate>;

	#[pallet::storage]
	type SrsChunks<T> = StorageValue<_, SrsChunksVec, ValueQuery>;

	#[pallet::storage]
	type Members<T> = StorageValue<_, <BandersnatchVrfVerifiable as GenerateVerifiable>::Members>;

	#[pallet::genesis_config]
	#[derive(frame_support::DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		#[serde(skip)]
		pub _phantom: sp_std::marker::PhantomData<T>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::make_empty_ring();
		}
	}

	/// Push a new ring member.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn push_member(
			origin: OriginFor<T>,
			member: <BandersnatchVrfVerifiable as GenerateVerifiable>::Member,
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

			log::debug!(target: LOG_TARGET, "Adding member {}", intermediate.ring.curr_keys);

			let srs_chunks = SrsChunks::<T>::get();

			let get_chunk = |i: usize| Ok(srs_chunks[i].clone());

			BandersnatchVrfVerifiable::push_member(&mut intermediate, member, get_chunk)
				.map_err(|_| Error::<T>::PushMemberFailure)?;
			log::debug!(target: LOG_TARGET, "Done");

			Intermediate::<T>::set(Some(intermediate));

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn finish_members(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			let Some(intermediate) = Intermediate::<T>::get() else {
				log::warn!(target: LOG_TARGET, "Ring not initialized");
				return Err(Error::<T>::RingNotInitialized.into())
			};

			log::debug!(target: LOG_TARGET, "Finalizing ring (members = {})", intermediate.ring.curr_keys);

			let members = BandersnatchVrfVerifiable::finish_members(intermediate);
			Members::<T>::set(Some(members));

			log::debug!(target: LOG_TARGET, "Done");

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(0)]
		pub fn reset_members(origin: OriginFor<T>) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			Members::<T>::kill();
			Self::make_empty_ring();

			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn make_empty_ring() {
			log::debug!(target: LOG_TARGET, "Initialize testing KZG for domain {}", DOMAIN_SIZE);
			let kzg = KZG::testing_kzg_setup([0; 32], DOMAIN_SIZE as u32);

			log::debug!(target: LOG_TARGET, "Initialize ring builder key");
			let ring_builder_key = RingBuilderKey::from_srs(&kzg.pcs_params, DOMAIN_SIZE);

			log::debug!(target: LOG_TARGET, "Initialize empty ring");
			let srs_chunks: Vec<_> =
				ring_builder_key.lis_in_g1.into_iter().map(|p| ArkScale(p)).collect();

			let get_chunks = |off: usize, len: usize| {
				let chunks: Vec<_> = srs_chunks[off..off + len].iter().cloned().collect();
				Ok(chunks)
			};
			let intermediate =
				BandersnatchVrfVerifiable::start_members(kzg.pcs_params.raw_vk(), get_chunks);
			Intermediate::<T>::set(Some(intermediate));

			// Persist SRS chunks for later usage
			log::debug!(target: LOG_TARGET, "SRS CHUNKS {}", srs_chunks.len());

			if SrsChunksVec::bound() < srs_chunks.len() {
				log::error!(
					target: LOG_TARGET,
					"Initialization failed. SRS bound {} but actual len is {}",
					SrsChunksVec::bound(),
					srs_chunks.len()
				);
				panic!("Bad SRS length");
			}
			SrsChunks::<T>::set(SrsChunksVec::truncate_from(srs_chunks));

			log::debug!(target: LOG_TARGET, "Initialization completed");
		}
	}
}
