const HashPreimageExample = artifacts.require("HashPreimageExample");

const crypto = require("crypto");

const fs = require("fs");
const ffi = require("ffi");
const ref = require("ref");
const BN = require("bn.js");

const VerifyingKeyPath = "../.keys/hashpreimage.vk.json";
const ProvingKeyPath = "../.keys/hashpreimage.pk.raw";

var native_library = ffi.Library("../.build/libhashpreimage", {
    // Create a proof for the parameters
    "hashpreimage_prove": [
        "string", [
            "string",       // pk_file
            "string",       // in_preimage
        ]
    ],

    // Verify a proof
    "hashpreimage_verify": [
        "bool", [
            "string",   // vk_json
            "string",   // proof_json
        ]
    ]
});



let list_flatten = (l) => {
    return [].concat.apply([], l);
};


let vk_to_flat = (vk) => {
    return [
        list_flatten([
            vk.alpha[0], vk.alpha[1],
            list_flatten(vk.beta),
            list_flatten(vk.gamma),
            list_flatten(vk.delta),
        ]),
        list_flatten(vk.gammaABC)
    ];
};


let proof_to_flat = (proof) => {
    return list_flatten([
        proof.A,
        list_flatten(proof.B),
        proof.C
    ]);
};


contract("HashPreimageExample", () => {
    describe("Prove & Verify", () => {
        const preimage = crypto.randomBytes(64);

        // Hash preimage, to be used as input to the contract
        const hasher = crypto.createHash('sha256');
        hasher.update(preimage);
        const preimage_hashed = new BN(hasher.digest('hex'), 16);

        // Load verification key
        const vk_json = fs.readFileSync(VerifyingKeyPath);
        const vk = JSON.parse(vk_json);

        var proof_json;
        var proof;

        it("native proof", async () => {
            // Run prover to generate proof
            proof_json = native_library.hashpreimage_prove(ProvingKeyPath, preimage);
            assert.notStrictEqual(proof_json, null);
            proof = JSON.parse(proof_json);
            //console.log('Proof is', proof);
        });

        it("native verify", async () => {
            // Re-verify proof using native library
            // XXX: node-ffi on OSX will not null-terminate strings returned from `readFileSync` !
            //console.log('Test verification using native library');
            const proof_valid_native = native_library.hashpreimage_verify(vk_json + '\0', proof_json);
            assert.strictEqual(proof_valid_native, true);
        });

        it("smart-contract verify (key-supplied)", async () => {
            let obj = await HashPreimageExample.deployed();

            // Test verification using the smart-contract
            const [vk_flat, vk_flat_IC] = vk_to_flat(vk);
            const test_verify_args = [
                vk_flat,                // (alpha, beta, gamma, delta)
                vk_flat_IC,             // gammaABC[]
                proof_to_flat(proof),   // A B C
                [  
                    proof.input[0],
                    proof.input[1],
                ]
            ];
            const test_verify_result = await obj.TestVerify(...test_verify_args);
            assert.strictEqual(test_verify_result, true);

        });

        it("smart-contract verify (key managed by contract)", async () => {
            let obj = await HashPreimageExample.deployed();

            // Verify whether or not our proof would be valid
            const proof_valid = await obj.Verify.call(
                [preimage_hashed.toString(10)],
                proof_to_flat(proof));
            assert.strictEqual(proof_valid, true);
        });
    });
});
