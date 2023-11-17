use dep::std::hash::poseidon::bn254 as poseidon;

struct SemaphoreIdentity {
    nullifier: Field,
    trapdoor: Field
}

impl SemaphoreIdentity {
    fn secret(self) -> Field {
        poseidon::hash_2([self.nullifier, self.trapdoor])
    }

    fn commitment(self) -> Field {
        poseidon::hash_1([self.secret()])
    }
}

fn calculate_nullifier_hash(identity_nullifier: Field, external_nullifier: Field) -> Field {
    poseidon::hash_2([external_nullifier, identity_nullifier])
}