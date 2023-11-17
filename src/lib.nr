use dep::std::hash::poseidon::bn254 as poseidon;

struct SemaphoreIdentity {
    nullifier: Field,
    trapdoor: Field
}

impl SemaphoreIdentity {
    fn secret(self) -> Field {
        poseidon::hash_2([self.nullifier, self.trapdoor])
    }

    fn identifier(self) -> Field {
        poseidon::hash_1([self.secret()])
    }

    fn nullifier_hash(self, external_nullifier: Field) -> Field {
        poseidon::hash_2([external_nullifier, self.nullifier])
    }
}