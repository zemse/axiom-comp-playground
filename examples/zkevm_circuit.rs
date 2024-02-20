/// Empty Circuit
///
/// This is intended as a basic boilerplate that can be copy pasted for new circuit.
///
use axiom_eth::{
    halo2_base::AssignedValue,
    halo2_proofs::{
        circuit::Layouter,
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    },
    rlc::circuit::builder::RlcCircuitBuilder,
    utils::{
        build_utils::dummy::DummyFrom,
        component::{
            circuit::{
                ComponentBuilder, CoreBuilder, CoreBuilderOutput, CoreBuilderOutputParams,
                CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::empty::EmptyPromiseLoader,
            types::{EmptyComponentType, LogicalEmpty},
        },
    },
    // Field,
};

use bus_mapping::circuit_input_builder::{FeatureConfig, FixedCParams};
use eth_types::Field;
use halo2_proofs::arithmetic::Field as Halo2Field;
use zkevm_circuits::super_circuit::{
    test::block_1tx, SuperCircuit, SuperCircuitConfig, SuperCircuitParams,
};

#[derive(Clone, Default)]
pub struct ZkevmCircuitParams;

impl CoreBuilderParams for ZkevmCircuitParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        // TODO see what this means
        CoreBuilderOutputParams::new(vec![1])
    }
}

// Private inputs to our circuit
#[derive(Clone, Default, Debug)]
pub struct ZkevmCircuitInput<F: Field> {
    super_circuit: Option<SuperCircuit<F>>,
}

impl<F: Field> DummyFrom<ZkevmCircuitParams> for ZkevmCircuitInput<F> {
    fn dummy_from(_seed: ZkevmCircuitParams) -> Self {
        ZkevmCircuitInput {
            super_circuit: Some(SuperCircuit::default()),
        }
    }
}

// Raw halo2 configuration
#[derive(Clone)]
pub struct ZkevmCircuitConfig<F: Field> {
    super_circuit: SuperCircuitConfig<F>,
}

// TODO reason why we have a circuit component struct as well as ZkevmCircuitInput
pub struct ZkevmCircuitBuilder<F: Field> {
    input: ZkevmCircuitInput<F>,
}

impl<F: Field> ComponentBuilder<F> for ZkevmCircuitBuilder<F> {
    type Config = ZkevmCircuitConfig<F>;

    type Params = ZkevmCircuitParams;

    fn new(_params: Self::Params) -> Self {
        Self {
            input: ZkevmCircuitInput {
                super_circuit: Some(SuperCircuit::default()),
            },
        }
    }

    fn get_params(&self) -> Self::Params {
        ZkevmCircuitParams
    }

    fn configure_with_params(
        _meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        ZkevmCircuitConfig {
            super_circuit: SuperCircuit::configure_with_params(
                _meta,
                SuperCircuitParams {
                    max_txs: 1,
                    max_withdrawals: 5,
                    max_calldata: 32,
                    mock_randomness: F::from(0x100),
                    feature_config: FeatureConfig {
                        zero_difficulty: true,
                        free_first_tx: false,
                        enable_eip1559: true,
                        invalid_tx: false,
                    },
                },
            ),
        }
    }

    fn calculate_params(&mut self) -> Self::Params {
        ZkevmCircuitParams
    }
}

impl<F: Field + Halo2Field> CoreBuilder<F> for ZkevmCircuitBuilder<F> {
    type CompType = EmptyComponentType<F>;

    type PublicInstanceValue = LogicalEmpty<F>;

    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;

    type CoreInput = ZkevmCircuitInput<F>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        // println!("feed_input {:?}", input);
        self.input = input;
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        _builder: &mut RlcCircuitBuilder<F>,
        _promise_caller: PromiseCaller<F>,
    ) -> CoreBuilderOutput<F, Self::CompType> {
        println!("virtual_assign_phase0");

        CoreBuilderOutput {
            public_instances: vec![],
            virtual_table: vec![],
            logical_results: vec![],
        }
    }

    fn raw_synthesize_phase0(&mut self, config: &Self::Config, layouter: &mut impl Layouter<F>) {
        println!("raw_synthesize_phase0");
        self.input
            .super_circuit
            .as_ref()
            .unwrap()
            .synthesize_2(config.super_circuit.clone(), layouter)
            .unwrap();
    }

    fn virtual_assign_phase1(&mut self, _builder: &mut RlcCircuitBuilder<F>) {
        println!("virtual_assign_phase1");
    }

    fn raw_synthesize_phase1(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        println!("raw_synthesize_phase1");
    }
}

use axiom_eth::{
    halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
    halo2curves::bn256::Fr,
    rlc::{circuit::RlcCircuitParams, virtual_region::RlcThreadBreakPoints},
    utils::component::{circuit::ComponentCircuitImpl, ComponentCircuit},
};

type ZkevmCircuit = ComponentCircuitImpl<Fr, ZkevmCircuitBuilder<Fr>, EmptyPromiseLoader<Fr>>;

#[tokio::main]
pub async fn main() {
    let k = 19;

    let circuit = ZkevmCircuit::new_from_stage(
        CircuitBuilderStage::Mock,
        ZkevmCircuitParams,
        (),
        RlcCircuitParams {
            base: BaseCircuitParams {
                k,
                num_advice_per_phase: vec![1, 1],
                num_fixed: 1,
                num_lookup_advice_per_phase: vec![],
                lookup_bits: Some(1),
                num_instance_columns: 1,
            },
            num_rlc_columns: 1,
        },
    )
    .use_break_points(RlcThreadBreakPoints {
        base: vec![vec![], vec![]],
        rlc: vec![],
    });

    let data = block_1tx();
    let circuits_params = FixedCParams {
        max_txs: 1,
        max_withdrawals: 5,
        max_calldata: 32,
        max_rws: 256,
        max_copy_rows: 256,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
    };
    let (k, super_circuit, instance, _) =
        SuperCircuit::<Fr>::build(data, circuits_params, Fr::from(0x100)).unwrap();

    // halo2_utils::info::print(&super_circuit);

    // let prover = MockProver::run(k, &super_circuit, _instance).unwrap();
    // println!("verifying constraints");
    // prover.assert_satisfied();

    // println!("done");
    // return;

    circuit
        .feed_input(Box::new(ZkevmCircuitInput {
            super_circuit: Some(super_circuit.clone()),
        }))
        .unwrap();

    println!("promise results fullfilled");

    println!("instance from super_circuit {:?}", instance);

    let public_instances = circuit.get_public_instances();
    let instances = vec![
        instance[0].clone(),
        instance[1].clone(),
        public_instances.into(),
    ];

    // halo2_utils::compare::compare_all(&super_circuit, &circuit, Some(k));
    // halo2_utils::assignments::print_all(&circuit, Some(k), Some(100));
    println!("running circuit");
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
    println!("success!");
}
