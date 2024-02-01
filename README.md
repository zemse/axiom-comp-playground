
```
cargo run 


virtual_assign_phase0

inputs SimpleCircuitInput { a: 0, b: 0 }

load witness a: AssignedValue { value: Trivial(0x0000000000000000000000000000000000000000000000000000000000000001), cell: Some(ContextCell { type_id: "halo2-base:SinglePhaseCoreManager:FirstPhase", context_id: 0, offset: 33345 }) }

PromiseCollector self println PromiseCollector { 
    dependencies_lookup: {"axiom-eth:ComponentTypeKeccak"}, 
    dependencies: ["axiom-eth:ComponentTypeKeccak"], 
    witness_grouped_calls: {}, 
    value_results: {}, 
    value_results_lookup: {}, 
    witness_commits: {
        "axiom-eth:ComponentTypeKeccak": AssignedValue { 
            value: Trivial(0x0000000000000000000000000000000000000000000000000000000000000000), 
            cell: Some(ContextCell { type_id: "halo2-base:SinglePhaseCoreManager:FirstPhase", context_id: 0, offset: 33344 }) 
        }
    }, 
    promise_results_ready: true 
}

PromiseCollector::call_impl

witness input KeccakFixLenCall { bytes: FixLenBytesVec { bytes: [SafeByte(AssignedValue { value: Trivial(0x0000000000000000000000000000000000000000000000000000000000000001), cell: Some(ContextCell { type_id: "halo2-base:SinglePhaseCoreManager:FirstPhase", context_id: 0, offset: 33345 }) })] } }

is virtual false

call_results None

thread 'main' panicked at /Users/sohamzemse/Workspace/axiom/static-call-work/axiom-eth/axiom-eth/src/utils/component/promise_collector.rs:193:30:
called `Option::unwrap()` on a `None` value
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

[/Users/sohamzemse/.cargo/git/checkouts/halo2-lib-d11b5da38eeddd90/2fe813b/halo2-base/src/virtual_region/lookups.rs:117] "WARNING: LookupAnyManager was not assigned!" = "WARNING: LookupAnyManager was not assigned!"
[/Users/sohamzemse/.cargo/git/checkouts/halo2-lib-d11b5da38eeddd90/2fe813b/halo2-base/src/virtual_region/copy_constraints.rs:122] "WARNING: advice_equalities not empty" = "WARNING: advice_equalities not empty"
[/Users/sohamzemse/.cargo/git/checkouts/halo2-lib-d11b5da38eeddd90/2fe813b/halo2-base/src/virtual_region/copy_constraints.rs:125] "WARNING: constant_equalities not empty" = "WARNING: constant_equalities not empty"
```
