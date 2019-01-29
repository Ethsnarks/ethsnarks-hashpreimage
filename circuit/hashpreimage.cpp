#include "hashpreimage.hpp"

#include "gadgets/sha256_many.cpp"
#include "utils.hpp"
#include "stubs.hpp"

#include <libff/algebra/fields/field_utils.hpp>

#include <openssl/sha.h>

namespace ethsnarks {


/**
* Verify that SHA256(private<secret>) == public<input>
*/
class mod_hashpreimage : public GadgetT
{
public:
    static const size_t SHA256_digest_size_bytes = libsnark::SHA256_digest_size / 8;

    static const size_t SHA256_block_size_bytes = libsnark::SHA256_block_size / 8;

    static const size_t secret_input_size_bits = libsnark::SHA256_block_size;

    static const size_t secret_input_size_bytes = secret_input_size_bits / 8;

    const size_t input_size_in_bits = libsnark::SHA256_digest_size;

    const size_t input_size_in_fields;

    const VariableArrayT public_inputs;

    const VariableArrayT secret_input_bits;

    sha256_many hasher;

    libsnark::multipacking_gadget<FieldT> packer;


    mod_hashpreimage(
        ProtoboardT &in_pb,
        const std::string &annotation_prefix
    ) :
        GadgetT(in_pb, annotation_prefix),

        // number of field packed elements as input
        input_size_in_fields( libff::div_ceil(input_size_in_bits, FieldT::capacity()) ),

        // public inputs
        public_inputs( make_var_array(in_pb, input_size_in_fields, FMT(annotation_prefix, ".public_inputs")) ),

        // Secret input bits
        secret_input_bits( make_var_array(in_pb, secret_input_size_bits, FMT(annotation_prefix, ".secret_input_bits")) ),

        // HASH(secret) -> packed(public_inputs)
        hasher(in_pb, secret_input_bits, FMT(annotation_prefix, ".hasher")),

        // pack the hash result into the input field elements
        packer(in_pb, hasher.result().bits, public_inputs, FieldT::capacity(), FMT(annotation_prefix, ".packer"))
    {
        in_pb.set_input_sizes( input_size_in_fields );
    }


    const libff::bit_vector digest_bits()
    {
        return hasher.result().bits.get_bits(this->pb);
    }


    void generate_r1cs_constraints()
    {
        hasher.generate_r1cs_constraints();

        // Output bits from hasher are already enforced to be bits
        packer.generate_r1cs_constraints(false);
    }


    void generate_r1cs_witness(
        const libff::bit_vector& in_secret_bv
    ) {
        // Fill secret bits
        assert( in_secret_bv.size() == secret_input_bits.size() );
        secret_input_bits.fill_with_bits(this->pb, in_secret_bv);

        // Hash the secret input
        hasher.generate_r1cs_witness();

        // Fill public inputs from the hash output bits
        packer.generate_r1cs_witness_from_bits();
    }


    /**
    * Given input bytes of SHA256 block size, generate the witness for the expected output
    */
    void generate_r1cs_witness(
        const uint8_t* in_secret
    ) {
        const auto input_bv = bytes_to_bv(in_secret, secret_input_size_bytes);

        this->generate_r1cs_witness( input_bv );
    }


    static PrimaryInputT make_primary_input(const libff::bit_vector &in_block_bv)
    {
        assert( in_block_bv.size() == secret_input_size_bits );

        return libff::pack_bit_vector_into_field_element_vector<FieldT>(in_block_bv);
    }
};

// namespace ethsnarks
}


using ethsnarks::ppT;
using ethsnarks::ProtoboardT;
using ethsnarks::mod_hashpreimage;


char *hashpreimage_prove( const char *pk_file, const uint8_t *preimage )
{
    ppT::init_public_params();

    ProtoboardT pb;
    mod_hashpreimage mod(pb, "module");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(preimage);

    if( ! pb.is_satisfied() )
    {
        return nullptr;
    }

    const auto json = ethsnarks::stub_prove_from_pb(pb, pk_file);

    return ::strdup(json.c_str());
}


int hashpreimage_genkeys( const char *pk_file, const char *vk_file )
{
    return ethsnarks::stub_genkeys<ethsnarks::mod_hashpreimage>(pk_file, vk_file);
}


bool hashpreimage_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}
