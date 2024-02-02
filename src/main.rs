mod factorisation_circuit;
use axiom_eth::halo2_proofs::dev::MockProver;

fn main() {
    // println!("public_instances {:?}", public_instances);
    // let instances = halo2_utils::infer_instance(&circuit, Some(k as u32));
    // println!("{:?}", instances);

    let (k, circuit, instances) = factorisation_circuit::get_circuit();
    halo2_utils::info::print(&circuit);

    println!("running circuit");
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
