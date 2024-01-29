use axiom_eth::{
    halo2_base::gates::circuit::{self, BaseCircuitParams, CircuitBuilderStage},
    halo2_proofs::dev::MockProver,
    halo2curves::bn256::{Fq, Fr},
    rlc::{circuit::RlcCircuitParams, virtual_region::RlcThreadBreakPoints},
    utils::component::{
        circuit::ComponentCircuitImpl, promise_loader::empty::EmptyPromiseLoader, ComponentCircuit,
    },
};

use crate::factorisation_circuit::{SimpleCircuit, SimpleCircuitParams};

mod factorisation_circuit;

#[derive(Default)]
struct PromiseLoaderParams {}

fn main() {
    let mut circuit =
        ComponentCircuitImpl::<Fr, SimpleCircuit, EmptyPromiseLoader<Fr>>::new_from_stage(
            CircuitBuilderStage::Mock,
            SimpleCircuitParams,
            (),
            RlcCircuitParams {
                base: BaseCircuitParams {
                    k: 15,
                    num_advice_per_phase: vec![1, 0],
                    num_fixed: 1,
                    num_lookup_advice_per_phase: vec![],
                    lookup_bits: Some(1),
                    num_instance_columns: 0,
                },
                num_rlc_columns: 0,
            },
        )
        .use_break_points(RlcThreadBreakPoints {
            base: vec![vec![], vec![]],
            rlc: vec![],
        });

    let ins = circuit.get_public_instances();
    println!("{:?}", ins);

    let instance = vec![vec![]];

    let prover = MockProver::run(15, &circuit, instance).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
