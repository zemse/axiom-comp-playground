#![feature(slice_flatten)]
use axiom_codec::{
    types::{
        field_elements::AnySubqueryResult,
        native::{AccountSubquery, StorageSubquery},
    },
    HiLo,
};
use axiom_eth::{
    halo2_base::{AssignedValue, Context},
    halo2_proofs::{circuit::*, dev::MockProver, plonk::*},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::*,
            promise_collector::PromiseCaller,
            promise_loader::combo::PromiseBuilderCombo,
            types::{EmptyComponentType, LogicalEmpty},
        },
    },
    zkevm_hashes::util::eth_types::ToScalar,
    Field,
};
use axiom_query::{
    components::subqueries::{
        account::types::{
            ComponentTypeAccountSubquery, FieldAccountSubqueryCall, OutputAccountShard,
        },
        storage::types::{
            ComponentTypeStorageSubquery, FieldStorageSubqueryCall, OutputStorageShard,
        },
    },
    utils::codec::{AssignedAccountSubquery, AssignedStorageSubquery},
};
use ethers_core::types::{Address, H256, U256};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

type AxiomAssignedValue<F> = AssignedValue<F>;
type Halo2AssignedCell<F> = AssignedCell<Assigned<F>, F>;

trait Assign<F: Field, A, H> {
    fn assign_axiom(&self, ctx: &mut Context<F>) -> A;

    fn assign_halo2(&self, config: &MultiConfig, layouter: &mut impl Layouter<F>) -> H;
}

mod account {
    use super::*;

    pub struct AccountPayload<AssignedType> {
        pub block_number: AssignedType,
        pub address: AssignedType,
        pub field_idx: AssignedType,
        pub value: HiLo<AssignedType>,
    }

    pub type AccountSubqueryResult = AnySubqueryResult<AccountSubquery, H256>;
    pub type AxiomAccountPayload<F> = AccountPayload<AxiomAssignedValue<F>>;
    pub type Halo2AccountPayload<F> = AccountPayload<Halo2AssignedCell<F>>;

    impl<F: Field> Assign<F, AxiomAccountPayload<F>, Halo2AccountPayload<F>> for AccountSubqueryResult {
        fn assign_axiom(&self, ctx: &mut Context<F>) -> AxiomAccountPayload<F> {
            AxiomAccountPayload::<F> {
                block_number: ctx.load_witness(F::from(self.subquery.block_number as u64)),
                address: ctx.load_witness(self.subquery.addr.to_scalar().unwrap()),
                field_idx: ctx.load_witness(F::from(self.subquery.field_idx as u64)),
                value: HiLo::<F>::from(self.value).assign(ctx),
            }
        }

        fn assign_halo2(
            &self,
            config: &MultiConfig,
            layouter: &mut impl Layouter<F>,
        ) -> Halo2AccountPayload<F> {
            layouter
                .assign_region(
                    || "myregion",
                    |mut region| {
                        let mut offset = 0;

                        let mut assign_advice = |value: F| {
                            let cell = region.assign_advice(
                                || format!("assign advice {offset} {value:?}"),
                                config.advice,
                                offset,
                                || Value::known(Assigned::Trivial(value)),
                            );
                            offset += 1;
                            cell
                        };
                        let block_number: AssignedCell<Assigned<F>, F> =
                            assign_advice(F::from(self.subquery.block_number as u64))?;
                        let address = assign_advice(self.subquery.addr.to_scalar().unwrap())?;
                        let field_idx = assign_advice(F::from(self.subquery.field_idx as u64))?;

                        let mut assign_hilo = |value: HiLo<F>| -> Result<_, Error> {
                            let [hi, lo] = value.hi_lo();
                            let hi = assign_advice(hi)?;
                            let lo = assign_advice(lo)?;
                            Ok(HiLo::from_lo_hi([hi, lo]))
                        };

                        let value = assign_hilo(HiLo::from(self.value))?;

                        Ok(Halo2AccountPayload {
                            block_number,
                            address,
                            field_idx,
                            value,
                        })
                    },
                )
                .unwrap()
        }
    }
}

mod storage {
    use eth_types::BigEndianHash;

    use super::*;

    pub struct StoragePayload<AssignedType> {
        pub block_number: AssignedType,
        pub address: AssignedType,
        pub slot: HiLo<AssignedType>,
        pub value: HiLo<AssignedType>,
    }

    pub type StorageSubqueryResult = AnySubqueryResult<StorageSubquery, H256>;
    pub type AxiomStoragePayload<F> = StoragePayload<AxiomAssignedValue<F>>;
    pub type Halo2StoragePayload<F> = StoragePayload<Halo2AssignedCell<F>>;

    impl<F: Field> Assign<F, AxiomStoragePayload<F>, Halo2StoragePayload<F>> for StorageSubqueryResult {
        fn assign_axiom(&self, ctx: &mut Context<F>) -> AxiomStoragePayload<F> {
            AxiomStoragePayload {
                block_number: ctx.load_witness(F::from(self.subquery.block_number as u64)),
                address: ctx.load_witness(self.subquery.addr.to_scalar().unwrap()),
                slot: HiLo::<F>::from(H256::from_uint(&self.subquery.slot)).assign(ctx),
                value: HiLo::<F>::from(self.value).assign(ctx),
            }
        }

        fn assign_halo2(
            &self,
            config: &MultiConfig,
            layouter: &mut impl Layouter<F>,
        ) -> Halo2StoragePayload<F> {
            layouter
                .assign_region(
                    || "myregion",
                    |mut region| {
                        let mut offset = 0;

                        let mut assign_advice = |value: F| {
                            let cell = region.assign_advice(
                                || format!("assign advice {offset} {value:?}"),
                                config.advice,
                                offset,
                                || Value::known(Assigned::Trivial(value)),
                            );
                            offset += 1;
                            cell
                        };
                        let block_number: AssignedCell<Assigned<F>, F> =
                            assign_advice(F::from(self.subquery.block_number as u64))?;
                        let address = assign_advice(self.subquery.addr.to_scalar().unwrap())?;

                        let mut assign_hilo = |value: HiLo<F>| -> Result<_, Error> {
                            let [hi, lo] = value.hi_lo();
                            let hi = assign_advice(hi)?;
                            let lo = assign_advice(lo)?;
                            Ok(HiLo::from_lo_hi([hi, lo]))
                        };
                        let slot = assign_hilo(HiLo::from(H256::from_uint(&self.subquery.slot)))?;
                        let value = assign_hilo(HiLo::from(self.value))?;

                        Ok(Halo2StoragePayload {
                            block_number,
                            address,
                            slot,
                            value,
                        })
                    },
                )
                .unwrap()
        }
    }
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct MultiInputs<F: Field> {
    accounts: Vec<account::AccountSubqueryResult>,
    storages: Vec<storage::StorageSubqueryResult>,
    _marker: PhantomData<F>,
}

impl<F: Field> MultiInputs<F> {
    fn accounts_assigned(
        &self,
        ctx: &mut Context<F>,
        promise_caller: &PromiseCaller<F>,
    ) -> Vec<[AssignedValue<F>; 2]> {
        self.accounts
            .iter()
            .map(|q| {
                let assigned = q.assign_axiom(ctx);
                promise_caller
                    .call::<FieldAccountSubqueryCall<F>, ComponentTypeAccountSubquery<F>>(
                        ctx,
                        FieldAccountSubqueryCall(AssignedAccountSubquery {
                            block_number: assigned.block_number,
                            addr: assigned.address,
                            field_idx: assigned.field_idx,
                        }),
                    )
                    .unwrap()
                    .hi_lo()
            })
            .collect()
    }
    fn storage_assigned(
        &self,
        ctx: &mut Context<F>,
        promise_caller: &PromiseCaller<F>,
    ) -> Vec<[AssignedValue<F>; 2]> {
        self.storages
            .iter()
            .map(|p| {
                let assigned = p.assign_axiom(ctx);
                promise_caller
                    .call::<FieldStorageSubqueryCall<F>, ComponentTypeStorageSubquery<F>>(
                        ctx,
                        FieldStorageSubqueryCall(AssignedStorageSubquery {
                            block_number: assigned.block_number,
                            addr: assigned.address,
                            slot: assigned.slot,
                        }),
                    )
                    .unwrap()
                    .hi_lo()
            })
            .collect()
    }

    fn assign_axiom(
        &self,
        ctx: &mut Context<F>,
        promise_caller: &PromiseCaller<F>,
    ) -> Vec<AssignedValue<F>> {
        self.storage_assigned(ctx, promise_caller)
            .iter()
            .chain(self.accounts_assigned(ctx, promise_caller).iter())
            .flatten()
            .copied()
            .collect_vec()
    }

    fn assign_halo2(
        &self,
        config: &MultiConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Vec<Halo2AssignedCell<F>> {
        todo!()
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct AccountInput<F: Field> {
    pub block_number: u64,
    pub address: Address,
    pub field_idx: u64,
    pub value: H256,
    pub _marker: PhantomData<F>,
}

pub struct AxiomAccountPayload<F: Field> {
    pub block_number: AxiomAssignedValue<F>,
    pub address: AxiomAssignedValue<F>,
    pub field_idx: AxiomAssignedValue<F>,
    pub value: HiLo<AxiomAssignedValue<F>>,
}

impl<F: Field> AccountInput<F> {
    pub fn assign_axiom(&self, ctx: &mut Context<F>) -> AxiomAccountPayload<F> {
        AxiomAccountPayload {
            block_number: ctx.load_witness(F::from(self.block_number)),
            address: ctx.load_witness(self.address.to_scalar().unwrap()),
            field_idx: ctx.load_witness(F::from(self.field_idx)),
            value: HiLo::<F>::from(self.value).assign(ctx),
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct StorageInput<F: Field> {
    pub block_number: u64,
    pub address: Address,
    pub slot: H256,
    pub value: H256,
    pub _marker: PhantomData<F>,
}

#[derive(Clone)]
pub struct MultiConfig {
    advice: Column<Advice>,
}

#[derive(Clone, Default)]
pub struct MultiInputParams;

impl CoreBuilderParams for MultiInputParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![])
    }
}
impl<F: Field> DummyFrom<MultiInputParams> for MultiInputs<F> {
    fn dummy_from(_seed: MultiInputParams) -> Self {
        MultiInputs::default()
    }
}

pub struct MultiInputsCircuitBuilder<F: Field> {
    input: Option<MultiInputs<F>>,
}

impl<F: Field> ComponentBuilder<F> for MultiInputsCircuitBuilder<F> {
    type Config = MultiConfig;

    type Params = MultiInputParams;

    fn new(_params: Self::Params) -> Self {
        Self { input: None }
    }

    fn get_params(&self) -> Self::Params {
        MultiInputParams
    }

    fn configure_with_params(
        meta: &mut axiom_eth::halo2_proofs::plonk::ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        Self::Config {
            advice: meta.advice_column(),
        }
    }

    fn calculate_params(&mut self) -> Self::Params {
        MultiInputParams
    }
}

impl<F: Field> CoreBuilder<F> for MultiInputsCircuitBuilder<F> {
    type CompType = EmptyComponentType<F>;

    type PublicInstanceValue = LogicalEmpty<F>;

    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;

    type CoreInput = MultiInputs<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        // TODO: This could be replaced with a more generic CircuitBuilder. Question: can be CircuitBuilder treated as something like PromiseCircuit?
        builder: &mut axiom_eth::rlc::circuit::builder::RlcCircuitBuilder<F>,
        // Core circuits can make promise calls.
        promise_caller: axiom_eth::utils::component::promise_collector::PromiseCaller<F>,
        // TODO: Output commitmment
    ) -> CoreBuilderOutput<F, Self::CompType> {
        println!("virtual_assign_phase0 my");

        let ctx = builder.base.main(0);

        let promise_results = self
            .input
            .as_ref()
            .unwrap()
            .assign_axiom(ctx, &promise_caller);

        CoreBuilderOutput {
            public_instances: promise_results, // this should not be public
            virtual_table: vec![],
            logical_results: vec![],
        }
    }

    fn raw_synthesize_phase0(
        &mut self,
        _config: &Self::Config,
        _layouter: &mut impl axiom_eth::halo2_proofs::circuit::Layouter<F>,
    ) {
        println!("raw_synthesize_phase0 my");
    }

    fn virtual_assign_phase1(
        &mut self,
        _builder: &mut axiom_eth::rlc::circuit::builder::RlcCircuitBuilder<F>,
    ) {
        println!("virtual_assign_phase1 my");
    }

    fn raw_synthesize_phase1(
        &mut self,
        _config: &Self::Config,
        _layouter: &mut impl axiom_eth::halo2_proofs::circuit::Layouter<F>,
    ) {
        println!("raw_synthesize_phase1 my");
    }
}

#[tokio::main]
async fn main() {
    use axiom_eth::{
        halo2curves::bn256::Fr,
        providers::setup_provider,
        utils::component::{
            circuit::ComponentCircuitImpl,
            promise_loader::single::{PromiseLoader, PromiseLoaderParams},
            ComponentCircuit, ComponentType,
        },
    };
    use axiom_query::components::{
        dummy_rlc_circuit_params, subqueries::common::shard_into_component_promise_results,
    };
    use ethers_core::types::{BigEndianHash, Chain, H256};
    use ethers_providers::Middleware;
    use std::marker::PhantomData;

    use axiom_query::components::subqueries::{
        account::types::ComponentTypeAccountSubquery, storage::types::ComponentTypeStorageSubquery,
    };

    type MultiPromiseLoader<F> = PromiseBuilderCombo<
        F,
        PromiseLoader<F, ComponentTypeAccountSubquery<F>>,
        PromiseLoader<F, ComponentTypeStorageSubquery<F>>,
    >;

    pub type MultiInputCircuit =
        ComponentCircuitImpl<Fr, MultiInputsCircuitBuilder<Fr>, MultiPromiseLoader<Fr>>;

    let k = 19;
    let storage_capacity = 10;
    let account_capacity = 10;

    let block_number = 19211974; // random block from 12 feb 2024

    #[derive(Clone, Copy)]
    enum AccountSubqueryField {
        Nonce = 0,
        Balance = 1,
        StorageRoot = 2,
    }

    // input from the witness
    let account_inputs: Vec<(&str, AccountSubqueryField)> = vec![
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            AccountSubqueryField::Nonce,
        ),
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            AccountSubqueryField::Balance,
        ),
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            AccountSubqueryField::StorageRoot,
        ),
    ];
    let storage_inputs = vec![
        ("0x60594a405d53811d3bc4766596efd80fd545a270", H256::zero()),
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            H256::from_uint(&U256::one()),
        ),
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            H256::from_uint(&U256::from(2)),
        ),
        (
            "0x60594a405d53811d3bc4766596efd80fd545a270",
            H256::from_uint(&U256::from(3)),
        ),
    ];

    // query data from rpc
    let provider = setup_provider(Chain::Mainnet);

    let mut account_subqueries = vec![];
    for (address, field_idx) in account_inputs {
        let proof = provider
            .get_proof(address, vec![], Some(block_number.into()))
            .await
            .unwrap();
        assert_eq!(proof.storage_proof.len(), 0);
        account_subqueries.push(account::AccountSubqueryResult {
            subquery: AccountSubquery {
                block_number: block_number as u32,
                addr: proof.address,
                field_idx: field_idx as u32,
            },
            value: match field_idx {
                AccountSubqueryField::Nonce => H256::from_uint(&U256::from(proof.nonce.as_u64())),
                AccountSubqueryField::Balance => H256::from_uint(&proof.balance),
                AccountSubqueryField::StorageRoot => proof.storage_hash,
            },
        });
    }

    let mut storage_subqueries = vec![];
    for (address, slot) in storage_inputs {
        let proof = provider
            .get_proof(address, vec![slot], Some(block_number.into()))
            .await
            .unwrap();
        assert_eq!(proof.storage_proof.len(), 1);
        // let proof = json_to_mpt_input(proof, 13, 0);
        storage_subqueries.push(storage::StorageSubqueryResult {
            subquery: StorageSubquery {
                block_number: block_number as u32,
                addr: proof.address,
                slot: proof.storage_proof[0].key.into_uint(),
            },
            value: H256::from_uint(&proof.storage_proof[0].value),
        });
    }

    let circuit_input = MultiInputs::<Fr> {
        accounts: account_subqueries,
        storages: storage_subqueries,
        _marker: PhantomData,
    };

    let mut circuit = MultiInputCircuit::new(
        MultiInputParams,
        (
            PromiseLoaderParams::new_for_one_shard(account_capacity),
            PromiseLoaderParams::new_for_one_shard(storage_capacity),
        ),
        dummy_rlc_circuit_params(k as usize),
    );
    circuit.feed_input(Box::new(circuit_input.clone())).unwrap();
    circuit.calculate_params();
    let promises = [
        (
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                OutputAccountShard {
                    results: circuit_input.accounts.clone(),
                }
                .into(),
            ),
        ),
        (
            ComponentTypeStorageSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeStorageSubquery<Fr>>(
                OutputStorageShard {
                    results: circuit_input.storages,
                }
                .into(),
            ),
        ),
    ]
    .into_iter()
    .collect();
    circuit.fulfill_promise_results(&promises).unwrap();
    println!("promise results fullfilled");
    let public_instances = circuit.get_public_instances();
    let instances = vec![public_instances.into()];

    println!("{:?}", instances);

    // halo2_utils::info::print(&circuit);

    println!("running circuit");
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
