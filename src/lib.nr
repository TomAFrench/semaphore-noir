use dep::std::hash::poseidon::bn254 as poseidon;
use dep::std::hash::keccak256;
use dep::std::field::bytes32_to_field;

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

pub fn calculate_nullifier_hash(external_nullifier: Field, identity_nullifier: Field) -> Field {
    poseidon::hash_2([external_nullifier, identity_nullifier])
}

// Hashes a value into a `Field` such that it may be used as an external nullifier.
pub fn hash_to_field(value: [u8]) -> Field {
    // We want to calculate `keccak256(value) >> 8`.
    // The bitshift ensures that the final value fits inside the scalar modulus of the snark field.

    let digest = keccak256(value, value.len() as u32);

    // A bitshift by 8 bits is equivalent to shifting each element in the digest right by 1
    // and setting the new first element equal to zero.
    let mut shifted_digest = [0; 32];
    for i in 0..31 {
        shifted_digest[i+1] = digest[i];
    }

    // We then sum this together to construct the field.
    bytes32_to_field(shifted_digest)
}

mod tests {
    use dep::std;
    use crate::hash_to_field;

    fn format_bytes32_string<N>(string: str<N>) -> [u8; 32] {
        assert(N as u32 <= 31, "string must be less than 32 bytes long");

        let mut output: [u8; 32] = [0; 32];

        let bytes = string.as_bytes();
        for i in 0..bytes.len() {
            output[i] = bytes[i];
        }

        output
    }

    #[test]
    fn hash_to_field_produces_expected_hash() {
        // Test taken from https://github.com/semaphore-protocol/semaphore/blob/94259e1865816c61727a8d3af3d9f20689a04e16/packages/proof/src/index.test.ts#L111
        let mut input = [0; 32];
        input[31] = 2;
        let expected_hash_field = 113682330006535319932160121224458771213356533826860247409332700812532759386;
        assert_eq(hash_to_field(input), expected_hash_field);
    }

    #[test]
    fn hash_to_field_produces_expected_hash_2() {
        // Test taken from https://github.com/semaphore-protocol/semaphore/blob/94259e1865816c61727a8d3af3d9f20689a04e16/packages/proof/src/index.test.ts#L99
        let mut input = format_bytes32_string("Hello world");

        let expected_hash_field = 8665846418922331996225934941481656421248110469944536651334918563951783029;
        assert_eq(hash_to_field(input.as_slice()), expected_hash_field);
    }
}
