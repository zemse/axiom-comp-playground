#![feature(slice_flatten)]
use axiom_codec::{
    types::native::{AccountSubquery, StorageSubquery},
    HiLo,
};
use axiom_eth::{
    halo2_base::{AssignedValue, Context},
    halo2_proofs::{circuit::*, dev::MockProver, plonk::*},
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::*,
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

#[derive(Clone, Default, Debug, Serialize)]
pub struct MultiInputs<F: Field> {
    accounts: Vec<AccountInput<F>>,
    storages: Vec<StorageInput<F>>,
}

impl<F: Field> MultiInputs<F> {
    pub fn assign_axiom(
        &self,
        ctx: &mut Context<F>,
    ) -> (Vec<AxiomAccountPayload<F>>, Vec<AxiomStoragePayload<F>>) {
        (
            self.accounts
                .iter()
                .map(|input| input.assign_axiom(ctx))
                .collect(),
            self.storages
                .iter()
                .map(|input| input.assign_axiom(ctx))
                .collect(),
        )
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

type AxiomAssignedValue<F> = AssignedValue<F>;
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

// type AxiomAssignedValue<F> = AssignedValue<F>;
pub struct AxiomStoragePayload<F: Field> {
    pub block_number: AxiomAssignedValue<F>,
    pub address: AxiomAssignedValue<F>,
    pub slot: HiLo<AxiomAssignedValue<F>>,
    pub value: HiLo<AxiomAssignedValue<F>>,
}

type Halo2AssignedCell<F> = AssignedCell<Assigned<F>, F>;
pub struct Halo2Payload<F: Field> {
    pub block_number: Halo2AssignedCell<F>,
    pub address: Halo2AssignedCell<F>,
    pub slot: HiLo<Halo2AssignedCell<F>>,
    pub value: HiLo<Halo2AssignedCell<F>>,
}

impl<F: Field> StorageInput<F> {
    pub fn assign_axiom(&self, ctx: &mut Context<F>) -> AxiomStoragePayload<F> {
        AxiomStoragePayload {
            block_number: ctx.load_witness(F::from(self.block_number)),
            address: ctx.load_witness(self.address.to_scalar().unwrap()),
            slot: HiLo::<F>::from(self.slot).assign(ctx),
            value: HiLo::<F>::from(self.value).assign(ctx),
        }
    }

    pub fn assign_halo2(
        &self,
        config: &SecretStorageConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Halo2Payload<F> {
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
                        assign_advice(F::from(self.block_number))?;
                    let address = assign_advice(self.address.to_scalar().unwrap())?;

                    let mut assign_hilo = |value: HiLo<F>| -> Result<_, Error> {
                        let [hi, lo] = value.hi_lo();
                        let hi = assign_advice(hi)?;
                        let lo = assign_advice(lo)?;
                        Ok(HiLo::from_lo_hi([hi, lo]))
                    };
                    let slot = assign_hilo(HiLo::from(self.slot))?;
                    let value = assign_hilo(HiLo::from(self.value))?;

                    Ok(Halo2Payload {
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

#[derive(Clone)]
pub struct SecretStorageConfig {
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
    type Config = SecretStorageConfig;

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

        let payload = self.input.as_ref().unwrap().assign_axiom(ctx);

        let account_assignments: Vec<[AssignedValue<F>; 2]> = payload
            .0
            .iter()
            .map(|p| {
                promise_caller
                    .call::<FieldAccountSubqueryCall<F>, ComponentTypeAccountSubquery<F>>(
                        ctx,
                        FieldAccountSubqueryCall(AssignedAccountSubquery {
                            block_number: p.block_number,
                            addr: p.address,
                            field_idx: p.field_idx,
                        }),
                    )
                    .unwrap()
                    .hi_lo()
            })
            .collect();

        let storage_assignments: Vec<[AssignedValue<F>; 2]> = payload
            .1
            .iter()
            .map(|p| {
                promise_caller
                    .call::<FieldStorageSubqueryCall<F>, ComponentTypeStorageSubquery<F>>(
                        ctx,
                        FieldStorageSubqueryCall(AssignedStorageSubquery {
                            block_number: p.block_number,
                            addr: p.address,
                            slot: p.slot,
                        }),
                    )
                    .unwrap()
                    .hi_lo()
            })
            .collect();

        CoreBuilderOutput {
            public_instances: account_assignments
                .flatten()
                .iter()
                .chain(storage_assignments.flatten().iter())
                .copied()
                .collect_vec(),
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
    use axiom_codec::types::field_elements::AnySubqueryResult;
    use axiom_eth::{
        halo2curves::bn256::Fr,
        providers::{setup_provider, storage::json_to_mpt_input},
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

    // input from the witness - list of addresses and storage slots
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

    let mut eth_account_inputs = vec![];
    for (address, field_idx) in account_inputs {
        let proof = provider
            .get_proof(address, vec![], Some(block_number.into()))
            .await
            .unwrap();
        assert_eq!(proof.storage_proof.len(), 0);
        // let proof = json_to_mpt_input(proof, 13, 0);
        eth_account_inputs.push((proof, field_idx));
    }

    let mut eth_storage_inputs = vec![];
    for (address, slot) in storage_inputs {
        let proof = provider
            .get_proof(address, vec![slot], Some(block_number.into()))
            .await
            .unwrap();
        assert_eq!(proof.storage_proof.len(), 1);
        let proof = json_to_mpt_input(proof, 13, 0);
        eth_storage_inputs.push(proof);
    }

    let input = MultiInputs::<Fr> {
        accounts: eth_account_inputs
            .iter()
            .map(|(proof, field_idx)| AccountInput {
                block_number,
                address: proof.address,
                field_idx: *field_idx as u64,
                value: match *field_idx {
                    AccountSubqueryField::Nonce => {
                        H256::from_uint(&U256::from(proof.nonce.as_u64()))
                    }
                    AccountSubqueryField::Balance => H256::from_uint(&proof.balance),
                    AccountSubqueryField::StorageRoot => proof.storage_hash,
                },
                _marker: PhantomData,
            })
            .collect(),
        storages: eth_storage_inputs
            .iter()
            .map(|proof| StorageInput {
                block_number,
                address: proof.addr,
                slot: proof.storage_pfs[0].0,
                value: H256::from_uint(&proof.storage_pfs[0].1),
                _marker: PhantomData,
            })
            .collect(),
    };
    println!("{:?}", input);

    let account_promise = OutputAccountShard {
        results: input
            .accounts
            .iter()
            .map(|s| AnySubqueryResult {
                subquery: AccountSubquery {
                    block_number: s.block_number as u32,
                    addr: s.address,
                    field_idx: s.field_idx as u32,
                },
                value: s.value,
            })
            .collect(),
    };
    let storage_promise = OutputStorageShard {
        results: input
            .storages
            .iter()
            .map(|s| AnySubqueryResult {
                subquery: StorageSubquery {
                    block_number: s.block_number as u32,
                    addr: s.address,
                    slot: U256::from_big_endian(&s.slot.to_fixed_bytes()),
                },
                value: s.value,
            })
            .collect(),
    };

    let mut circuit = MultiInputCircuit::new(
        MultiInputParams,
        (
            PromiseLoaderParams::new_for_one_shard(account_capacity),
            PromiseLoaderParams::new_for_one_shard(storage_capacity),
        ),
        dummy_rlc_circuit_params(k as usize),
    );
    circuit.feed_input(Box::new(input)).unwrap();
    circuit.calculate_params();
    let promises = [
        (
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                account_promise.into(),
            ),
        ),
        (
            ComponentTypeStorageSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeStorageSubquery<Fr>>(
                storage_promise.into(),
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
