/// Factorisation Circuit
///
/// Goal is to learn Axiom component framework by creating a simple circuit.
///
/// In this example we want to prove the knowledge of two numbers which are factors of a public number.
///
use axiom_eth::{
    halo2_base::AssignedValue,
    halo2_proofs::{
        circuit::{Layouter, Value},
        plonk::{Advice, Column, ConstraintSystem},
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
            types::{EmptyComponentType, LogicalEmpty},
        },
    },
    Field,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default)]
pub struct SimpleCircuitParams;

impl CoreBuilderParams for SimpleCircuitParams {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        // TODO see what this means
        CoreBuilderOutputParams::new(vec![1])
    }
}

/// Circuit input for a single Account subquery.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SimpleCircuitInput {
    a: u64,
    b: usize,
}

impl DummyFrom<SimpleCircuitParams> for SimpleCircuitInput {
    fn dummy_from(_seed: SimpleCircuitParams) -> Self {
        SimpleCircuitInput { a: 1, b: 2 }
    }
}

#[derive(Clone)]
pub struct SimpleCircuitConfig {
    advice: Column<Advice>,
}

pub struct SimpleCircuit {
    input: SimpleCircuitInput,
}

impl<F: Field> ComponentBuilder<F> for SimpleCircuit {
    type Config = SimpleCircuitConfig;

    type Params = SimpleCircuitParams;

    fn new(_params: Self::Params) -> Self {
        Self {
            input: SimpleCircuitInput::default(),
        }
    }

    fn get_params(&self) -> Self::Params {
        SimpleCircuitParams
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        SimpleCircuitConfig {
            advice: meta.advice_column(),
        }
    }

    fn calculate_params(&mut self) -> Self::Params {
        SimpleCircuitParams
    }
}

impl<F: Field> CoreBuilder<F> for SimpleCircuit {
    type CompType = EmptyComponentType<F>;

    type PublicInstanceValue = LogicalEmpty<F>;

    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;

    type CoreInput = SimpleCircuitInput;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = input;
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        // TODO: This could be replaced with a more generic CircuitBuilder. Question: can be CircuitBuilder treated as something like PromiseCircuit?
        _builder: &mut RlcCircuitBuilder<F>,
        // Core circuits can make promise calls.
        _promise_caller: PromiseCaller<F>,
        // TODO: Output commitmment
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
        let _cell = layouter
            .assign_region(
                || "myregion",
                |mut region| {
                    region.assign_advice(
                        || "advice a",
                        config.advice,
                        0,
                        || Value::known(F::from(self.input.a)),
                    )?;
                    region.assign_advice(
                        || "advice b",
                        config.advice,
                        0,
                        || Value::known(F::from(self.input.a)),
                    )
                },
            )
            .unwrap();
        // layouter.constrain_instance(cell.cell(), column, row)
    }

    fn virtual_assign_phase1(&mut self, _builder: &mut RlcCircuitBuilder<F>) {
        println!("virtual_assign_phase1");
    }

    fn raw_synthesize_phase1(&mut self, _config: &Self::Config, _layouter: &mut impl Layouter<F>) {
        println!("raw_synthesize_phase1");
    }
}
