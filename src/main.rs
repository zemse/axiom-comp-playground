use axiom_eth::{
    halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
    halo2_proofs::dev::MockProver,
    halo2curves::bn256::Fr,
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    rlc::{circuit::RlcCircuitParams, virtual_region::RlcThreadBreakPoints},
    utils::component::{
        circuit::ComponentCircuitImpl,
        promise_loader::comp_loader::SingleComponentLoaderParams,
        promise_loader::single::{PromiseLoader, PromiseLoaderParams},
        ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
    },
};

use crate::factorisation_circuit::{SimpleCircuit, SimpleCircuitInput, SimpleCircuitParams};

mod factorisation_circuit;

fn main() {
    let k = 22;
    let keccak_f_capacity = 200;

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
                k,
                num_advice_per_phase: vec![1, 1],
                num_fixed: 2,
                num_lookup_advice_per_phase: vec![1, 1],
                lookup_bits: Some(2),
                num_instance_columns: 1,
            },
            num_rlc_columns: 1,
        },
    )
    .use_break_points(RlcThreadBreakPoints {
        base: vec![vec![], vec![]],
        rlc: vec![],
    });

    circuit
        .feed_input(Box::new(SimpleCircuitInput { a: 3, b: 7 }))
        .unwrap();

    let promises = [(
        ComponentTypeKeccak::<Fr>::get_type_id(),
        ComponentPromiseResultsInMerkle::from_single_shard(
            generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                .unwrap()
                .into_logical_results(),
        ),
    )]
    .into_iter()
    .collect();
    circuit.fulfill_promise_results(&promises).unwrap();

    println!("promise results fullfilled");

    // let instances = halo2_utils::infer_instance(&circuit, Some(k as u32));
    // println!("{:?}", instances);

    let public_instances = circuit.get_public_instances();
    // println!("public_instances {:?}", public_instances);

    let instances = vec![public_instances.into()];

    // halo2_utils::info::print(&circuit)

    println!("running circuit");
    let prover = MockProver::run(k as u32, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
