mod factorisation_circuit;
mod secret_account_circuit;
use axiom_eth::halo2_proofs::dev::MockProver;

#[tokio::main]
async fn main() {
    // println!("public_instances {:?}", public_instances);
    // let instances = halo2_utils::infer_instance(&circuit, Some(k as u32));
    // println!("{:?}", instances);

    // let (k, circuit, instances) = factorisation_circuit::get_circuit();
    let (k, circuit, instances) = secret_account_circuit::circuit::generate().await;
    // halo2_utils::info::print(&circuit);

    println!("running circuit");
    let prover = MockProver::run(k, &circuit, instances).unwrap();
    println!("verifying constraints");
    prover.assert_satisfied();
}
