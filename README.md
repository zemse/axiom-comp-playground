
```
cargo run 


virtual_assign_phase0
ComponentPublicInstances { output_commit: 0x0000000000000000000000000000000000000000000000000000000000000000, promise_result_commit: 0x14b2e5484b232721d64f405caa487febbce835dd07c5de940f2a775dc9aa0da6, other: [] }
virtual_assign_phase0
raw_synthesize_phase0
virtual_assign_phase1
raw_synthesize_phase1
verifying constraints
Equality constraint not satisfied by cell (Column('Advice', 1 - ), outside any region, on row 6746)

Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 1)

thread 'main' panicked at /Users/sohamzemse/.cargo/registry/src/index.crates.io-6f17d22bba15001f/halo2-axiom-0.4.2/src/dev.rs:1549:13:
circuit was not satisfied
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```
