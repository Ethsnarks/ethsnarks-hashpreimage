#include "utils.hpp"
#include "stubs.hpp"
#include "hashpreimage.cpp"


using ethsnarks::ppT;
using ethsnarks::ProtoboardT;
using ethsnarks::bytes_to_bv;
using ethsnarks::bv_to_bytes;
using ethsnarks::print_bv;
using ethsnarks::mod_hashpreimage;


int main( int argc, char **argv )
{
	// Types for board
	ppT::init_public_params();

    const auto SHA256_block_size_bytes = mod_hashpreimage::SHA256_block_size_bytes;
    const auto SHA256_digest_size_bytes = mod_hashpreimage::SHA256_digest_size_bytes;

    const uint8_t input_buffer[SHA256_block_size_bytes] = {
        0x9F, 0x86, 0xD0, 0x81, 0x88, 0x4C, 0x7D, 0x65, 0x9A, 0x2F, 0xEA, 0xA0, 0xC5, 0x5A, 0xD0, 0x15,
        0xA3, 0xBF, 0x4F, 0x1B, 0x2B, 0x0B, 0x82, 0x2C, 0xD1, 0x5D, 0x6C, 0x15, 0xB0, 0xF0, 0x0A, 0x08,
        0x9F, 0x86, 0xD0, 0x81, 0x88, 0x4C, 0x7D, 0x65, 0x9A, 0x2F, 0xEA, 0xA0, 0xC5, 0x5A, 0xD0, 0x15,
        0xA3, 0xBF, 0x4F, 0x1B, 0x2B, 0x0B, 0x82, 0x2C, 0xD1, 0x5D, 0x6C, 0x15, 0xB0, 0xF0, 0x0A, 0x08
    };
    const auto input_buffer_bv = bytes_to_bv(input_buffer, SHA256_block_size_bytes);

    const uint8_t output_expected[SHA256_digest_size_bytes] = {
        0xD2, 0x94, 0xF6, 0xE5, 0x85, 0x87, 0x4F, 0xE6,
        0x40, 0xBE, 0x4C, 0xE6, 0x36, 0xE6, 0xEF, 0x9E,
        0x3A, 0xDC, 0x27, 0x62, 0x0A, 0xA3, 0x22, 0x1F,
        0xDC, 0xF5, 0xC0, 0xA7, 0xC1, 0x1C, 0x6F, 0x67};
    const auto output_expected_bv = bytes_to_bv(output_expected, SHA256_digest_size_bytes);

    // Setup new preimage hash
    ProtoboardT pb;
    mod_hashpreimage mod(pb, "module");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(input_buffer_bv);
	if( ! pb.is_satisfied() )
	{
		std::cerr << "FAIL circuit not satisfied\n";
		return 1;
	}

    // Verify output is as expected
    const auto full_output_bits = mod.digest_bits();
    uint8_t full_output_bytes[SHA256_digest_size_bytes];
    bv_to_bytes(full_output_bits, full_output_bytes);
    if( memcmp(full_output_bytes, output_expected, SHA256_digest_size_bytes) != 0 )
    {
        std::cerr << "FAIL output doesnt match\n";

        print_bv("output bits", full_output_bits);
        print_bv("expect bits", output_expected_bv);

        for( size_t i = 0; i < SHA256_digest_size_bytes; i++ )
        {
            if( full_output_bytes[i] != output_expected[i] )
            {
                std::cerr << "Error at " << i << " expected " << int(output_expected[i]) << " got " << int(full_output_bytes[i]) << "\n";
                return 3;
            }
        }

        return 2;
    }

    if( ! ethsnarks::stub_test_proof_verify(pb) ) {
        std::cerr << "FAIL could not prove\n";
        return 4;
    }

    return 0;
}
