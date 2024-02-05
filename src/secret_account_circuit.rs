use std::marker::PhantomData;

use axiom_codec::HiLo;
/// Secret Account Circuit
///
/// In this example we want to prove that we are aware of a special ethereum address
/// whose state root is something specific.
///
use axiom_eth::{
    halo2_base::AssignedValue,
    halo2_proofs::{
        circuit::{AssignedCell, Layouter, Value},
        plonk::{Advice, Column},
    },
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::{
                ComponentBuilder, CoreBuilder, CoreBuilderOutput, CoreBuilderOutputParams,
                CoreBuilderParams,
            },
            types::{EmptyComponentType, LogicalEmpty},
        },
    },
    zkevm_hashes::util::eth_types::ToScalar,
    Field,
};
use axiom_query::{
    components::subqueries::account::types::{
        ComponentTypeAccountSubquery, FieldAccountSubqueryCall,
    },
    utils::codec::AssignedAccountSubquery,
};
use ethers_core::types::{Address, H256};
use serde::{Deserialize, Serialize};

/// Circuit input for a single Account subquery.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CircuitInputSecretAccountSubquery {
    /// The block number to access the account state at.
    pub block_number: u64,
    /// Account proof formatted as MPT input. `proof.storage_pfs` will be empty.
    /// It will contain the correct state root of the block.
    pub address: Address,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct SecretAccountInputs<F: Field> {
    pub request: CircuitInputSecretAccountSubquery,
    pub response: H256,
    pub _phantom: PhantomData<F>,
}

pub struct Payload<F: Field> {
    pub block_number: AssignedCell<F, F>,
    pub address: AssignedCell<F, F>,
    pub storage_root_hi: AssignedCell<F, F>,
    pub storage_root_lo: AssignedCell<F, F>,
}

#[derive(Default)]
pub struct SecretAccountCircuitBuilder<F: Field> {
    inputs: Option<SecretAccountInputs<F>>,
    payload: Option<Payload<F>>,
}

#[derive(Clone)]
pub struct SecretAccountConfig {
    advice: Column<Advice>,
}

#[derive(Clone, Default)]
pub struct SecretAccountParams;

impl<F: Field> ComponentBuilder<F> for SecretAccountCircuitBuilder<F> {
    type Config = SecretAccountConfig;

    type Params = SecretAccountParams;

    fn new(_params: Self::Params) -> Self {
        Self::default()
    }

    fn get_params(&self) -> Self::Params {
        SecretAccountParams
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
        SecretAccountParams
    }
}

impl<F: Field> DummyFrom<SecretAccountParams> for SecretAccountInputs<F> {
    fn dummy_from(_seed: SecretAccountParams) -> Self {
        SecretAccountInputs::default()
    }
}

impl CoreBuilderParams for SecretAccountParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        // TODO see what this means
        CoreBuilderOutputParams::new(vec![1])
    }
}

impl<F: Field> CoreBuilder<F> for SecretAccountCircuitBuilder<F> {
    type CompType = EmptyComponentType<F>;

    type PublicInstanceValue = LogicalEmpty<F>;

    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;

    type CoreInput = SecretAccountInputs<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.inputs = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        builder: &mut axiom_eth::rlc::circuit::builder::RlcCircuitBuilder<F>,
        promise_caller: axiom_eth::utils::component::promise_collector::PromiseCaller<F>,
    ) -> axiom_eth::utils::component::circuit::CoreBuilderOutput<F, Self::CompType> {
        println!("virtual_assign_phase0");
        let ctx = builder.base.main(0);
        let block_number =
            ctx.load_witness(F::from(self.inputs.as_ref().unwrap().request.block_number));
        let addr = ctx.load_witness(
            self.inputs
                .as_ref()
                .unwrap()
                .request
                .address
                .to_scalar()
                .unwrap(),
        );
        let account_storage_hash_idx = ctx.load_constant(F::from(2));

        let account_subquery = AssignedAccountSubquery {
            block_number,
            addr,
            field_idx: account_storage_hash_idx,
        };
        let promise_storage_root = promise_caller
            .call::<FieldAccountSubqueryCall<F>, ComponentTypeAccountSubquery<F>>(
                ctx,
                FieldAccountSubqueryCall(account_subquery),
            )
            .unwrap();
        // TODO constrain equal promise_storage_root and advice storage_root in raw halo2 side

        CoreBuilderOutput {
            public_instances: vec![promise_storage_root.hi(), promise_storage_root.lo()],
            virtual_table: vec![],
            logical_results: vec![],
        }
    }

    fn raw_synthesize_phase0(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {
        println!("raw_synthesize_phase0");
        // we can do raw halo2 synthesis stuff here
        let [block_number, address, storage_root_hi, storage_root_lo]: [AssignedCell<F, F>; 4] =
            layouter
                .assign_region(
                    || "myregion",
                    |mut region| {
                        let inputs = self.inputs.as_ref().unwrap();
                        let block_number = region.assign_advice(
                            || "advice block number",
                            config.advice,
                            0,
                            || Value::known(F::from(inputs.request.block_number)),
                        )?;
                        let address = region.assign_advice(
                            || "advice address",
                            config.advice,
                            1,
                            || Value::known(inputs.request.address.to_scalar().unwrap()),
                        )?;
                        let storage_root = HiLo::<F>::from(inputs.response);
                        let storage_root_hi = region.assign_advice(
                            || "advice storage root hi",
                            config.advice,
                            2,
                            || Value::known(storage_root.hi()),
                        )?;
                        let storage_root_lo = region.assign_advice(
                            || "advice storage root lo",
                            config.advice,
                            3,
                            || Value::known(storage_root.lo()),
                        )?;
                        Ok([block_number, address, storage_root_hi, storage_root_lo])
                    },
                )
                .unwrap();

        self.payload = Some(Payload {
            block_number,
            address,
            storage_root_hi,
            storage_root_lo,
        });
    }
}

pub mod circuit {
    use axiom_codec::types::{field_elements::AnySubqueryResult, native::AccountSubquery};
    use axiom_eth::{
        halo2curves::bn256::Fr,
        mpt::KECCAK_RLP_EMPTY_STRING,
        providers::{setup_provider, storage::json_to_mpt_input},
        utils::component::{
            circuit::ComponentCircuitImpl,
            promise_loader::single::{PromiseLoader, PromiseLoaderParams},
            ComponentCircuit, ComponentType,
        },
    };
    use axiom_query::components::{
        dummy_rlc_circuit_params,
        subqueries::{
            account::types::{ComponentTypeAccountSubquery, OutputAccountShard},
            common::shard_into_component_promise_results,
        },
    };
    use ethers_core::types::{Chain, H256};
    use ethers_providers::Middleware;
    use std::marker::PhantomData;

    use crate::secret_account_circuit::SecretAccountParams;

    use super::CircuitInputSecretAccountSubquery;
    use super::SecretAccountCircuitBuilder;
    use super::SecretAccountInputs;

    type CAccount<F> = ComponentTypeAccountSubquery<F>;

    pub type SecretAccountCircuit =
        ComponentCircuitImpl<Fr, SecretAccountCircuitBuilder<Fr>, PromiseLoader<Fr, CAccount<Fr>>>;

    pub async fn generate() -> (u32, SecretAccountCircuit, Vec<Vec<Fr>>) {
        // parameters
        let k = 19;
        let account_capacity = 2;

        // witness
        let block_number = 17143006;
        let address = "0x0000000000000000000000000000000000000000";

        // query data from rpc
        let provider = setup_provider(Chain::Mainnet);
        let proof = provider
            .get_proof(address, vec![], Some(block_number.into()))
            .await
            .unwrap();
        let storage_root = if proof.storage_hash.is_zero() {
            // RPC provider may give zero storage hash for empty account, but the correct storage hash should be the null root = keccak256(0x80)
            H256::from_slice(&KECCAK_RLP_EMPTY_STRING)
        } else {
            proof.storage_hash
        };
        assert_eq!(
            proof.storage_proof.len(),
            0,
            "Storage proof should have length 0 exactly"
        );

        // TODO this is mostly not needed as this will be done in account component
        let proof = json_to_mpt_input(proof, 13, 0);

        // our circuit inputs
        let request = CircuitInputSecretAccountSubquery {
            block_number,
            address: proof.addr,
        };
        let input = SecretAccountInputs::<Fr> {
            request,
            response: storage_root,
            _phantom: PhantomData,
        };

        // list of promise queries and responses into account component
        let promise_account = OutputAccountShard {
            results: vec![AnySubqueryResult {
                subquery: AccountSubquery {
                    block_number: block_number as u32,
                    field_idx: 2, // Storage root field
                    addr: proof.addr,
                },
                value: storage_root,
            }],
        };

        // circuit object
        let mut circuit = SecretAccountCircuit::new(
            SecretAccountParams,
            PromiseLoaderParams::new_for_one_shard(account_capacity),
            dummy_rlc_circuit_params(k as usize),
        );
        circuit.feed_input(Box::new(input)).unwrap();
        circuit.calculate_params();
        let promises = [(
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                promise_account.into(),
            ),
        )]
        .into_iter()
        .collect();
        circuit.fulfill_promise_results(&promises).unwrap();
        println!("promise results fullfilled");

        let public_instances = circuit.get_public_instances();
        let instances = vec![public_instances.into()];

        println!("{:?}", instances);

        (k as u32, circuit, instances)
    }
}
