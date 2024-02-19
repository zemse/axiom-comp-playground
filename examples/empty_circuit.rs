/// Empty Circuit
///
/// This is intended as a basic boilerplate that can be copy pasted for new circuit.
///
use axiom_eth::{
    halo2_base::AssignedValue,
    halo2_proofs::{circuit::Layouter, dev::MockProver, plonk::ConstraintSystem},
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
    Field,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct EmptyCircuitParams;

impl CoreBuilderParams for EmptyCircuitParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        // TODO see what this means
        CoreBuilderOutputParams::new(vec![1])
    }
}

// Private inputs to our circuit
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct EmptyCircuitInput;

impl DummyFrom<EmptyCircuitParams> for EmptyCircuitInput {
    fn dummy_from(_seed: EmptyCircuitParams) -> Self {
        EmptyCircuitInput
    }
}

// Raw halo2 configuration
#[derive(Clone)]
pub struct EmptyCircuitConfig;

// TODO reason why we have a circuit component struct as well as EmptyCircuitInput
pub struct EmptyCircuitBuilder {
    input: EmptyCircuitInput,
}

impl<F: Field> ComponentBuilder<F> for EmptyCircuitBuilder {
    type Config = EmptyCircuitConfig;

    type Params = EmptyCircuitParams;

    fn new(_params: Self::Params) -> Self {
        Self {
            input: EmptyCircuitInput,
        }
    }

    fn get_params(&self) -> Self::Params {
        EmptyCircuitParams
    }

    fn configure_with_params(
        _meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        EmptyCircuitConfig
    }

    fn calculate_params(&mut self) -> Self::Params {
        EmptyCircuitParams
    }
}

impl<F: Field> CoreBuilder<F> for EmptyCircuitBuilder {
    type CompType = EmptyComponentType<F>;

    type PublicInstanceValue = LogicalEmpty<F>;

    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;

    type CoreInput = EmptyCircuitInput;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        println!("feed_input {:?}", input);
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

    fn raw_synthesize_phase0(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        println!("raw_synthesize_phase0");
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

type EmptyCircuit = ComponentCircuitImpl<Fr, EmptyCircuitBuilder, EmptyPromiseLoader<Fr>>;

#[tokio::main]
pub async fn main() {
    let k = 19;

    let circuit = EmptyCircuit::new_from_stage(
        CircuitBuilderStage::Mock,
        EmptyCircuitParams,
        (),
        RlcCircuitParams {
            base: BaseCircuitParams {
                k,
                num_advice_per_phase: vec![6, 1],
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

    circuit.feed_input(Box::new(EmptyCircuitInput)).unwrap();

    println!("promise results fullfilled");

    let public_instances = circuit.get_public_instances();

    let instances = vec![public_instances.into()];

    println!("running circuit");
    let prover = MockProver::run(k as u32, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
