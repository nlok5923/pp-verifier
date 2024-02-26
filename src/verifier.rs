use crate::constants::{ConstantParams, Constants};
use crate::groth_16::{G1Point, G2Point, Groth16};
use alloy_primitives::U256;
use alloy_sol_types::sol;
use stylus_sdk::prelude::*;
sol_storage! {
    #[entrypoint]
    pub struct Verifier {}
}

sol! {
    struct VerifyingKey {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[2] IC;
    }

    struct Proof {
        G1Point A;
        G2Point B;
        G1Point C;
    }
}

#[external]
impl Verifier {
    #[allow(non_snake_case)]
    pub fn verifyProof(words: [U256; 9]) -> Result<bool, Vec<u8>> {
        let proof: [U256; 8] = words[0..8].try_into().unwrap();
        let input: [U256; 1] = vec![words[8]].try_into().unwrap();

        let mut i = 0;
        while i < 8 {
            if proof[i] >= Constants.PRIME_Q() {
                return Err("first verify".into());
            }
            i += 1;
        }

        let proof = Proof {
            A: G1Point {
                X: proof[0],
                Y: proof[1],
            },
            B: G2Point {
                X: [proof[2], proof[3]],
                Y: [proof[4], proof[5]],
            },
            C: G1Point {
                X: proof[6],
                Y: proof[7],
            },
        };

        let verifying_key = Verifier::verifyingKey()?;

        let vk_x = G1Point {
            X: U256::from(0),
            Y: U256::from(0),
        };
        let mut vk_x = Groth16::plus(&vk_x, &verifying_key.IC[0])?;

        #[allow(clippy::needless_range_loop)]
        for z in 0..1 {
            if input[z] >= Constants.SNARK_SCALAR_FIELD() {
                return Err("sunade".into());
            }
            let scalarmul = Groth16::scalar_mul(&verifying_key.IC[z + 1], input[z])?;
            let val2 = Groth16::plus(&vk_x, &scalarmul)?;
            vk_x = val2;
        }

        Groth16::pairing(
            Groth16::negate(proof.A),
            proof.B,
            verifying_key.alfa1,
            verifying_key.beta2,
            vk_x,
            verifying_key.gamma2,
            proof.C,
            verifying_key.delta2,
        )
    }
}

impl Verifier {
    #[allow(non_snake_case)]
    pub fn verifyingKey() -> Result<VerifyingKey, Vec<u8>> {
        let alfa1 = G1Point {
            X: U256::from_be_bytes([45, 77, 154, 167, 227, 2, 217, 223, 65, 116, 157, 85, 7, 148, 157, 5, 219, 234, 51, 251, 177, 108, 100, 59, 34, 245, 153, 162, 190, 109, 242, 226]),
            Y: U256::from_be_bytes([20, 190, 221, 80, 60, 55, 206, 176, 97, 216, 236, 96, 32, 159, 227, 69, 206, 137, 131, 10, 25, 35, 3, 1, 240, 118, 202, 255, 0, 77, 25, 38]),
        };
        let beta2 = G2Point {
            X: [
                U256::from_be_bytes([9, 103, 3, 47, 203, 247, 118, 209, 175, 201, 133, 248, 136, 119, 241, 130, 211, 132, 128, 166, 83, 242, 222, 202, 169, 121, 76, 188, 59, 243, 6, 12]),
                U256::from_be_bytes([14, 24, 120, 71, 173, 76, 121, 131, 116, 208, 214, 115, 43, 245, 1, 132, 125, 214, 139, 192, 224, 113, 36, 30, 2, 19, 188, 127, 193, 61, 183, 171]),
            ],
            Y: [
                U256::from_be_bytes([48, 76, 251, 209, 224, 138, 112, 74, 153, 245, 232, 71, 217, 63, 140, 60, 170, 253, 222, 196, 107, 122, 13, 55, 157, 166, 154, 77, 17, 35, 70, 167]),
                U256::from_be_bytes([23, 57, 193, 177, 164, 87, 168, 199, 49, 49, 35, 210, 77, 47, 145, 146, 248, 150, 183, 198, 62, 234, 5, 169, 213, 127, 6, 84, 122, 208, 206, 200]),
            ],
        };
        let gamma2 = G2Point {
            X: [
                U256::from_be_bytes([25, 142, 147, 147, 146, 13, 72, 58, 114, 96, 191, 183, 49, 251, 93, 37, 241, 170, 73, 51, 53, 169, 231, 18, 151, 228, 133, 183, 174, 243, 18, 194]),
                U256::from_be_bytes([24, 0, 222, 239, 18, 31, 30, 118, 66, 106, 0, 102, 94, 92, 68, 121, 103, 67, 34, 212, 247, 94, 218, 221, 70, 222, 189, 92, 217, 146, 246, 237]),
            ],
            Y: [
                U256::from_be_bytes([9, 6, 137, 208, 88, 95, 240, 117, 236, 158, 153, 173, 105, 12, 51, 149, 188, 75, 49, 51, 112, 179, 142, 243, 85, 172, 218, 220, 209, 34, 151, 91]),
                U256::from_be_bytes([18, 200, 94, 165, 219, 140, 109, 235, 74, 171, 113, 128, 141, 203, 64, 143, 227, 209, 231, 105, 12, 67, 211, 123, 76, 230, 204, 1, 102, 250, 125, 170]),
            ],
        };

        let delta2 = G2Point {
            X: [
                U256::from_be_bytes([36, 129, 71, 247, 127, 163, 122, 61, 249, 124, 246, 101, 212, 42, 209, 246, 48, 12, 83, 245, 94, 196, 225, 237, 20, 254, 154, 45, 20, 41, 53, 141]),
                U256::from_be_bytes([33, 228, 184, 165, 147, 65, 179, 236, 240, 110, 215, 189, 207, 85, 131, 71, 144, 186, 98, 54, 66, 96, 183, 88, 126, 204, 207, 137, 161, 12, 2, 114]),
            ],
            Y: [
                U256::from_be_bytes([0, 24, 111, 117, 13, 169, 233, 196, 100, 72, 70, 9, 95, 148, 206, 107, 228, 230, 236, 124, 20, 144, 73, 92, 68, 177, 213, 231, 153, 227, 209, 34]),
                U256::from_be_bytes([9, 32, 244, 243, 182, 193, 143, 84, 249, 42, 151, 25, 87, 178, 42, 205, 61, 223, 178, 40, 254, 103, 2, 53, 55, 50, 127, 8, 10, 180, 52, 25]),
            ],
        };

        let ic = [
            G1Point {
                X: U256::from_be_bytes([19, 116, 130, 72, 202, 63, 108, 185, 183, 224, 35, 157, 227, 125, 33, 222, 23, 199, 8, 75, 208, 165, 130, 157, 187, 126, 142, 176, 38, 2, 13, 157]),
                Y: U256::from_be_bytes([37, 42, 217, 130, 54, 22, 50, 105, 87, 197, 78, 206, 200, 69, 234, 29, 88, 36, 1, 121, 0, 4, 152, 186, 202, 71, 187, 45, 34, 104, 253, 41]),
            },
            G1Point {
                X: U256::from_be_bytes([14, 135, 130, 100, 133, 5, 137, 150, 33, 88, 156, 150, 243, 10, 118, 118, 39, 69, 155, 85, 119, 171, 211, 222, 112, 202, 115, 152, 28, 19, 226, 40]),
                Y: U256::from_be_bytes([2, 6, 239, 240, 30, 194, 119, 160, 132, 155, 94, 18, 28, 14, 63, 182, 8, 188, 245, 169, 181, 240, 187, 38, 248, 48, 38, 54, 55, 47, 144, 170]),
            },
        ];
        Ok(VerifyingKey {
            alfa1,
            beta2,
            gamma2,
            delta2,
            IC: ic,
        })
    }
}
