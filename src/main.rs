use axiom_eth::{
    halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
    halo2_proofs::dev::MockProver,
    halo2curves::bn256::Fr,
    keccak::types::ComponentTypeKeccak,
    rlc::{circuit::RlcCircuitParams, virtual_region::RlcThreadBreakPoints},
    utils::component::{
        circuit::ComponentCircuitImpl,
        promise_loader::comp_loader::SingleComponentLoaderParams,
        promise_loader::single::{PromiseLoader, PromiseLoaderParams},
    },
};

use crate::factorisation_circuit::{SimpleCircuit, SimpleCircuitParams};

mod factorisation_circuit;

fn main() {
    let circuit = ComponentCircuitImpl::<
        Fr,
        SimpleCircuit,
        PromiseLoader<Fr, ComponentTypeKeccak<Fr>>,
    >::new_from_stage(
        CircuitBuilderStage::Mock,
        SimpleCircuitParams,
        PromiseLoaderParams {
            comp_loader_params: SingleComponentLoaderParams::new(2, vec![1]),
        },
        RlcCircuitParams {
            base: BaseCircuitParams {
                k: 16,
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

    let instances = halo2_utils::infer_instance(&circuit, None);
    println!("{:?}", instances);

    // let instances = vec![vec![]];

    let prover = MockProver::run(15, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
