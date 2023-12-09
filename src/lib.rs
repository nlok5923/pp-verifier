// Only run this as a WASM if the export-abi feature is not set.
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

mod constants;

/// Initializes a custom, global allocator for Rust programs compiled to WASM.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use alloy_sol_types::sol;
use constants::{ConstantParams, Constants};
use stylus_sdk::{
    alloy_primitives::{address, U256},
    call::RawCall,
    prelude::*,
};

sol_storage! {
    #[entrypoint]
    pub struct Verifier {}

    pub struct Groth16 {}
}

sol! {
    #[derive(Copy)]
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    struct VerifyingKey {
        G1Point alfa1;
        G2Point beta2;
        G2Point gamma2;
        G2Point delta2;
        G1Point[7] IC;
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
    pub fn verifyProof() -> Result<(), Vec<u8>> {
        todo!()
    }
}

impl Groth16 {
    pub fn negate(p: G1Point) -> G1Point {
        if p.X == U256::ZERO && p.Y == U256::ZERO {
            G1Point {
                X: U256::ZERO,
                Y: U256::ZERO,
            }
        } else {
            G1Point {
                X: p.X,
                Y: Constants.PRIME_Q() - (p.Y % Constants.PRIME_Q()),
            }
        }
    }

    pub fn plus(p1: G1Point, p2: G1Point) -> Result<G1Point, Vec<u8>> {
        let calldata = [p1.X, p1.Y, p2.X, p2.Y]
            .map(|i| i.to_be_bytes::<32>())
            .concat();
        let call_result = RawCall::new_static().gas(u64::MAX).call(
            address!("0000000000000000000000000000000000000006"),
            &calldata,
        );
        if call_result.is_err() {
            return Err(call_result.err().unwrap());
        }
        let returndata = call_result.unwrap();
        Ok(G1Point {
            X: U256::from_be_bytes::<32>(returndata[0..32].try_into().unwrap()),
            Y: U256::from_be_bytes::<32>(returndata[32..64].try_into().unwrap()),
        })
    }

    pub fn scalar_mul(p1: G1Point, s: U256) -> Result<G1Point, Vec<u8>> {
        let calldata = [p1.X, p1.Y, s].map(|i| i.to_be_bytes::<32>()).concat();
        // let calldata = ;
        let call_result = RawCall::new_static().gas(u64::MAX).call(
            address!("0000000000000000000000000000000000000007"),
            &calldata,
        );

        if call_result.is_err() {
            return Err(call_result.err().unwrap());
        }

        let returndata = call_result.unwrap();
        Ok(G1Point {
            X: U256::from_be_bytes::<32>(returndata[0..32].try_into().unwrap()),
            Y: U256::from_be_bytes::<32>(returndata[32..64].try_into().unwrap()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pairing(
        a1: G1Point,
        a2: G2Point,
        b1: G1Point,
        b2: G2Point,
        c1: G1Point,
        c2: G2Point,
        d1: G1Point,
        d2: G2Point,
    ) -> Result<bool, Vec<u8>> {
        let p1 = [a1, b1, c1, d1];
        let p2 = [a2, b2, c2, d2];

        let mut input = [U256::ZERO; 24];

        for i in 0..4 {
            let j = i * 6;
            input[j] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        let calldata = input.map(|i| i.to_be_bytes::<32>()).concat();
        let call_result = RawCall::new_static().gas(u64::MAX).call(
            address!("0000000000000000000000000000000000000008"),
            &calldata,
        );
        if call_result.is_err() {
            return Err("pairing-opcode-failed".as_bytes().to_vec());
        }
        let returndata = call_result.unwrap();
        let len = U256::from_be_bytes::<32>(returndata[0..32].try_into().unwrap());
        Ok(len != U256::from(0))
    }

    fn verifyingKey() -> Result<VerifyingKey, Vec<u8>> {
        let alfa1 = G1Point {
            X: "20692898189092739278193869274495556617788530808486270118371701516666252877969"
                .parse()
                .unwrap(),
            Y: "11713062878292653967971378194351968039596396853904572879488166084231740557279"
                .parse()
                .unwrap(),
        };
        let beta2 = G2Point {
            X: [
                "12168528810181263706895252315640534818222943348193302139358377162645029937006"
                    .parse()
                    .unwrap(),
                "281120578337195720357474965979947690431622127986816839208576358024608803542"
                    .parse()
                    .unwrap(),
            ],
            Y: [
                "16129176515713072042442734839012966563817890688785805090011011570989315559913"
                    .parse()
                    .unwrap(),
                "9011703453772030375124466642203641636825223906145908770308724549646909480510"
                    .parse()
                    .unwrap(),
            ],
        };
        let gamma2 = G2Point {
            X: [
                "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                    .parse()
                    .unwrap(),
                "10857046999023057135944570762232829481370756359578518086990519993285655852781"
                    .parse()
                    .unwrap(),
            ],
            Y: [
                "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                    .parse()
                    .unwrap(),
                "8495653923123431417604973247489272438418190587263600148770280649306958101930"
                    .parse()
                    .unwrap(),
            ],
        };

        let delta2 = G2Point {
            X: [
                "21280594949518992153305586783242820682644996932183186320680800072133486887432"
                    .parse()
                    .unwrap(),
                "150879136433974552800030963899771162647715069685890547489132178314736470662"
                    .parse()
                    .unwrap(),
            ],
            Y: [
                "1081836006956609894549771334721413187913047383331561601606260283167615953295"
                    .parse()
                    .unwrap(),
                "11434086686358152335540554643130007307617078324975981257823476472104616196090"
                    .parse()
                    .unwrap(),
            ],
        };

        let ic = [G1Point {
            X: Default::default(),
            Y: Default::default(),
        }; 7];
        ic[0] = G1Point {
            X: "16225148364316337376768119297456868908427925829817748684139175309620217098814"
                .parse()
                .unwrap(),
            Y: "5167268689450204162046084442581051565997733233062478317813755636162413164690"
                .parse()
                .unwrap(),
        };
        ic[1]  = G1Point{
            X: "12882377842072682264979317445365303375159828272423495088911985689463022094260".parse().unwrap(),
            Y: "19488215856665173565526758360510125932214252767275816329232454875804474844786".parse().unwrap()
        };
        ic[2] = G1Point{
            X:"13083492661683431044045992285476184182144099829507350352128615182516530014777".parse().unwrap(),
            Y:"602051281796153692392523702676782023472744522032670801091617246498551238913".parse().unwrap()
        };
        ic[3] = G1Point{
            X:""
        }
    }

    // vk.alfa1 = Pairing.G1Point(
    //     uint256(
    //         20692898189092739278193869274495556617788530808486270118371701516666252877969
    //     ),
    //     uint256(
    //         11713062878292653967971378194351968039596396853904572879488166084231740557279
    //     )
    // );
    // vk.beta2 = Pairing.G2Point(
    //     [
    //         uint256(
    //             12168528810181263706895252315640534818222943348193302139358377162645029937006
    //         ),
    //         uint256(
    //             281120578337195720357474965979947690431622127986816839208576358024608803542
    //         )
    //     ],
    //     [
    //         uint256(
    //             16129176515713072042442734839012966563817890688785805090011011570989315559913
    //         ),
    //         uint256(
    //             9011703453772030375124466642203641636825223906145908770308724549646909480510
    //         )
    //     ]
    // );
    // vk.gamma2 = Pairing.G2Point(
    //     [
    //         uint256(
    //             11559732032986387107991004021392285783925812861821192530917403151452391805634
    //         ),
    //         uint256(
    //             10857046999023057135944570762232829481370756359578518086990519993285655852781
    //         )
    //     ],
    //     [
    //         uint256(
    //             4082367875863433681332203403145435568316851327593401208105741076214120093531
    //         ),
    //         uint256(
    //             8495653923123431417604973247489272438418190587263600148770280649306958101930
    //         )
    //     ]
    // );
    // vk.delta2 = Pairing.G2Point(
    //     [
    //         uint256(
    //             21280594949518992153305586783242820682644996932183186320680800072133486887432
    //         ),
    //         uint256(
    //             150879136433974552800030963899771162647715069685890547489132178314736470662
    //         )
    //     ],
    //     [
    //         uint256(
    //             1081836006956609894549771334721413187913047383331561601606260283167615953295
    //         ),
    //         uint256(
    //             11434086686358152335540554643130007307617078324975981257823476472104616196090
    //         )
    //     ]
    // );
    // vk.IC[0] = Pairing.G1Point(
    //     uint256(
    //         16225148364316337376768119297456868908427925829817748684139175309620217098814
    //     ),
    //     uint256(
    //         5167268689450204162046084442581051565997733233062478317813755636162413164690
    //     )
    // );
    // vk.IC[1] = Pairing.G1Point(
    //     uint256(
    //         12882377842072682264979317445365303375159828272423495088911985689463022094260
    //     ),
    //     uint256(
    //         19488215856665173565526758360510125932214252767275816329232454875804474844786
    //     )
    // );
    // vk.IC[2] = Pairing.G1Point(
    //     uint256(
    //         13083492661683431044045992285476184182144099829507350352128615182516530014777
    //     ),
    //     uint256(
    //         602051281796153692392523702676782023472744522032670801091617246498551238913
    //     )
    // );
    // vk.IC[3] = Pairing.G1Point(
    //     uint256(
    //         9732465972180335629969421513785602934706096902316483580882842789662669212890
    //     ),
    //     uint256(
    //         2776526698606888434074200384264824461688198384989521091253289776235602495678
    //     )
    // );
    // vk.IC[4] = Pairing.G1Point(
    //     uint256(
    //         8586364274534577154894611080234048648883781955345622578531233113180532234842
    //     ),
    //     uint256(
    //         21276134929883121123323359450658320820075698490666870487450985603988214349407
    //     )
    // );
    // vk.IC[5] = Pairing.G1Point(
    //     uint256(
    //         4910628533171597675018724709631788948355422829499855033965018665300386637884
    //     ),
    //     uint256(
    //         20532468890024084510431799098097081600480376127870299142189696620752500664302
    //     )
    // );
    // vk.IC[6] = Pairing.G1Point(
    //     uint256(
    //         15335858102289947642505450692012116222827233918185150176888641903531542034017
    //     ),
    //     uint256(
    //         5311597067667671581646709998171703828965875677637292315055030353779531404812
    //     )
    // );
}
