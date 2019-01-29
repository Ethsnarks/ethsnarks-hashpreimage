pragma solidity ^0.5.0;

import "../../ethsnarks/contracts/Verifier.sol";
import "../../ethsnarks/contracts/SnarkUtils.sol";

contract HashPreimageExample
{
    // Store the verification key
    uint256[14] private m_vk;
    uint256[] private m_gammaABC;

    // Construct instance of contract with a verification key
    constructor( uint256[14] memory in_vk, uint256[] memory in_gammaABC )
        public
    {
        m_vk = in_vk;
        m_gammaABC = in_gammaABC;
    }


    function TestVerify (
        uint256[14] memory in_vk,
        uint256[] memory vk_gammaABC,
        uint256[8] memory in_proof,
        uint256[] memory proof_inputs
    )
        public view returns (bool)
    {
        return Verifier.Verify(in_vk, vk_gammaABC, in_proof, proof_inputs);
    }


    // Provide proof of knowledge of a hash preimage
    function Verify(
        uint256[] memory in_data,
        uint256[8] memory proof
    )
        public view returns (bool)
    {
        // Public inputs for the zkSNARK circuit are hashed into a single input
        // A 256bit word is packed into two 253bit field elements
        uint256[] memory snark_input = new uint256[](2);
        SnarkUtils.PackWords(in_data, snark_input);

        // Validate the proof
        return Verifier.Verify( m_vk, m_gammaABC, proof, snark_input );
    }
}
