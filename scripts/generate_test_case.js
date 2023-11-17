const { Identity } = require("@semaphore-protocol/identity");
const { calculateNullifierHash } = require("@semaphore-protocol/proof");
const { appendFileSync } = require("fs");
const { resolve } = require('path');
const { BigNumber } = require("@ethersproject/bignumber");
const { zeroPad } = require("@ethersproject/bytes");
const { keccak256 } = require("@ethersproject/keccak256");

/**
 * Creates a keccak256 hash of a message compatible with the SNARK scalar modulus.
 * @param message The message to be hashed.
 * @returns The message digest.
 */
function hash(message) {
  message = BigNumber.from(message).toTwos(256).toHexString()
  message = zeroPad(message, 32)

  return (BigInt(keccak256(message)) >> BigInt(8)).toString()
}

function generateTestCase() {
  const identity = new Identity()
  const externalNullifier = 1234567890

  const expectedNullifierHash = calculateNullifierHash(identity.nullifier, externalNullifier);

  const test_case_id = identity.commitment.toString().slice(0,10); 
  const noir_test_case = `

#[test]
fn test_semaphore_${test_case_id}() {
  let identity = SemaphoreIdentity {
    nullifier: ${identity.nullifier},
    trapdoor: ${identity.trapdoor}
  };

  assert_eq(identity.secret(), ${identity.secret}, "incorrect secret");
  assert_eq(identity.commitment(), ${identity.commitment}, "incorrect identifier");

  assert_eq(calculate_nullifier_hash(identity.nullifier, ${hash(externalNullifier)}), ${expectedNullifierHash});
}
`

  appendFileSync(resolve("src/lib.nr"), noir_test_case)

}

function main() {
  const num_test_cases = parseInt(process.argv[2]) || 1;
  for (let i = 0; i < num_test_cases; i++) {
    generateTestCase()
  }
}


main()