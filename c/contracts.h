#ifndef CONTRACTS_H_
#define CONTRACTS_H_

#include "sha256.h"
#include "ripemd160.h"
#include "mbedtls/bignum.h"

/* Protocol Params:
   [Referenced]: https://github.com/ethereum/go-ethereum/blob/master/params/protocol_params.go
*/
#define SHA256_BASE_GAS       60  // Base price for a SHA256 operation
#define SHA256_PERWORD_GAS    12  // Per-word price for a SHA256 operation
#define RIPEMD160_BASE_GAS    600 // Base price for a RIPEMD160 operation
#define RIPEMD160_PERWORD_GAS 120 // Per-word price for a RIPEMD160 operation
#define IDENTITY_BASE_GAS     15  // Base price for a data copy operation
#define IDENTITY_PERWORD_GAS  3   // Per-work price for a data copy operation

#define BLAKE2F_INPUT_LENGTH          213
#define BLAKE2F_FINAL_BLOCK_BYTES     0x1
#define BLAKE2F_NON_FINAL_BLOCK_BYTES 0x0

#define ERROR_MOD_EXP  -23
#define ERROR_BLAKE2F  -24

/* pre-compiled Ethereum contracts */

typedef int (*precompiled_contract_gas_fn)(const uint8_t *input_src,
                                           const size_t input_size,
                                           uint64_t *gas);
typedef int (*precompiled_contract_fn)(gw_context_t *ctx,
                                       const uint8_t *input_src,
                                       const size_t input_size,
                                       uint8_t **output,
                                       size_t *output_size);

int ecrecover_required_gas(const uint8_t *input, const size_t input_size, uint64_t *gas) {
  // Elliptic curve sender recovery gas price
  *gas = 3000;
  return 0;
}

/*
  The input data: (hash, v, r, s), each 32 bytes
  ===============
    input[0 ..32]  => hash
    input[32..64]  => v (padded)
         [64]      => v
    input[64..128] => signature[0..64]
         [64..96 ] => r (u256)
         [96..128] => s (u256)
*/
int ecrecover(gw_context_t *ctx,
              const uint8_t *input_src,
              const size_t input_size,
              uint8_t **output, size_t *output_size) {

  int ret;
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
#ifdef GW_GENERATOR
  ret = ckb_secp256k1_custom_verify_only_initialize(ctx, &context, secp_data);
#else
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
#endif
  if (ret != 0) {
    return ret;
  }

  uint8_t input[128];
  memcpy(input, input_src, input_size);
  /* RightPadBytes */
  for (size_t i = input_size; i < 128; i++) {
    input[i] = 0;
  }
  for (int i = 32; i < 63; i ++) {
    if (input[i] != 0) {
      ckb_debug("input[32:63] not all zero!");
      return -1;
    }
  }
  /* FIXME: crypto.ValidateSignatureValues(v, r, s, false) */

  int recid = input[63] - 27;
  uint8_t signature_data[64];
  memcpy(signature_data, input + 64, 32);
  memcpy(signature_data + 32, input + 96, 32);
  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(&context, &signature, signature_data, recid) == 0) {
    ckb_debug("parse signature failed");
    return -1;
  }
  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, input) != 1) {
    ckb_debug("recover public key failed");
    return -1;
  }

  /* Check pubkey hash */
  uint8_t temp[65];
  size_t pubkey_size = 33;
  if (secp256k1_ec_pubkey_serialize(&context, temp,
                                    &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    ckb_debug("public key serialize failed");
    return -1;
  }

  union ethash_hash256 hash_result = ethash::keccak256(temp + 1, 64);
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    return -1;
  }
  memset(output, 0, 12);
  memcpy(output + 12, hash_result.bytes + 12, 20);
  *output_size = 32;
  return 0;
}

int sha256hash_required_gas(const uint8_t *input, const size_t input_size, uint64_t *gas) {
  *gas = (uint64_t)(input_size + 31) / 32 * SHA256_PERWORD_GAS + SHA256_BASE_GAS;
  return 0;
}


int sha256hash(gw_context_t *ctx,
               const uint8_t *input_src,
               const size_t input_size,
               uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(32);
  if (*output == NULL) {
    return -1;
  }
  *output_size = 32;
  SHA256_CTX hash_ctx;
  sha256_init(&hash_ctx);
  sha256_update(&hash_ctx, input_src, input_size);
  sha256_final(&hash_ctx, *output);
  return 0;
}


int ripemd160hash_required_gas(const uint8_t *input, const size_t input_size, uint64_t *gas) {
  *gas = (uint64_t)(input_size + 31) / 32 * RIPEMD160_PERWORD_GAS + RIPEMD160_BASE_GAS;
  return 0;
}


int ripemd160hash(gw_context_t *ctx,
               const uint8_t *input_src,
               const size_t input_size,
               uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(20);
  if (*output == NULL) {
    return -1;
  }
  *output_size = 20;
  ripemd160(input_src, input_size, *output);
  return 0;
}

int data_copy_required_gas(const uint8_t *input, const size_t input_size, uint64_t *gas) {
  *gas = (uint64_t)(input_size + 31) / 32 * IDENTITY_PERWORD_GAS + IDENTITY_BASE_GAS;
  return 0;
}


int data_copy(gw_context_t *ctx,
                  const uint8_t *input_src,
                  const size_t input_size,
                  uint8_t **output, size_t *output_size) {
  *output = (uint8_t *)malloc(input_size);
  if (*output == NULL) {
    return -1;
  }
  *output_size = input_size;
  memcpy(*output, input_src, input_size);
  return 0;
}

int read_lens(const uint8_t *input,
              const size_t input_size,
              mbedtls_mpi *base_len,
              mbedtls_mpi *exp_len,
              mbedtls_mpi *mod_len,
              size_t *base_size,
              size_t *exp_size,
              size_t *mod_size) {
  int ret;
  mbedtls_mpi_init(base_len);
  mbedtls_mpi_init(exp_len);
  mbedtls_mpi_init(mod_len);
  ret = mbedtls_mpi_read_binary(base_len, input, 32);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_read_binary(exp_len, input + 32, 32);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_read_binary(mod_len, input + 64, 32);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }

  ret = mbedtls_mpi_write_binary_le(base_len, (unsigned char *)(base_size), sizeof(size_t));
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_write_binary_le(exp_len, (unsigned char *)(exp_size), sizeof(size_t));
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_write_binary_le(mod_len, (unsigned char *)(mod_size), sizeof(size_t));
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  return 0;
}

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198
//
// def mult_complexity(x):
//    if x <= 64: return x ** 2
//    elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//    else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
uint128_t modexp_mult_complexity(uint128_t x) {
  if (x <= 64) {
    return x * x;
  } else if (x <= 1024) {
    return x * x / 4 + 96 * x - 3072;
  } else {
    return x * x / 16 + 480 * x - 199680;
  }
}

int big_mod_exp_required_gas(const uint8_t *input, const size_t input_size, uint64_t *target_gas) {
  int ret;
  mbedtls_mpi base_len;
  mbedtls_mpi exp_len;
  mbedtls_mpi mod_len;
  size_t base_size;
  size_t exp_size;
  size_t mod_size;
  ret = read_lens(input, input_size,
                  &base_len, &exp_len, &mod_len,
                  &base_size, &exp_size, &mod_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }

  const uint8_t *content = input_size > 96 ? input + 96 : NULL;
  const size_t content_size = content != NULL ? input_size - 96 : 0;
  if (content_size < (base_size + exp_size + mod_size)) {
    return ERROR_MOD_EXP;
  }

	// Retrieve the head 32 bytes of exp for the adjusted exponent length
  mbedtls_mpi exp_head;
  mbedtls_mpi_init(&exp_head);
  size_t exp_head_size = exp_size > 32 ? 32 : exp_size;
  ret = mbedtls_mpi_read_binary(&exp_head, content + base_size, exp_head_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
	// Calculate the adjusted exponent length
  int msb = 0;
  int exp_head_bitlen = mbedtls_mpi_bitlen(&exp_head);
  if (exp_head_bitlen > 0) {
    msb = exp_head_bitlen - 1;
  }
  mbedtls_mpi adj_exp_len;
  mbedtls_mpi_init(&adj_exp_len);
  if (exp_size > 32) {
    ret = mbedtls_mpi_sub_int(&adj_exp_len, &exp_len, 32);
    if (ret != 0) {
      return ERROR_MOD_EXP;
    }
    ret = mbedtls_mpi_mul_int(&adj_exp_len, &adj_exp_len, 8);
    if (ret != 0) {
      return ERROR_MOD_EXP;
    }
  }
  ret = mbedtls_mpi_add_int(&adj_exp_len, &adj_exp_len, msb);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
	// Calculate the gas cost of the operation
  size_t base_gas = mod_size > base_size ? mod_size : base_size;
  uint128_t gas = modexp_mult_complexity((uint128_t)base_gas);
  mbedtls_mpi gas_big;
  mbedtls_mpi_init(&gas_big);
  ret = mbedtls_mpi_read_binary_le(&gas_big, (unsigned char *)(&gas), 16);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  if (mbedtls_mpi_cmp_int(&adj_exp_len, 1) > 0) {
    ret = mbedtls_mpi_mul_mpi(&gas_big, &gas_big, &adj_exp_len);
    if (ret != 0) {
      return ERROR_MOD_EXP;
    }
  }
  ret = mbedtls_mpi_div_int(&gas_big, NULL, &gas_big, 20);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }

  if (mbedtls_mpi_bitlen(&gas_big) > 64) {
    *target_gas = UINT64_MAX;
  } else {
    ret = mbedtls_mpi_write_binary_le(&gas_big, (unsigned char *)(&target_gas), sizeof(target_gas));
    if (ret != 0) {
      return ERROR_MOD_EXP;
    }
  }
  return 0;
}


int big_mod_exp(gw_context_t *ctx,
                const uint8_t *input_src,
                const size_t input_size,
                uint8_t **output, size_t *output_size) {
  int ret;
  mbedtls_mpi base_len;
  mbedtls_mpi exp_len;
  mbedtls_mpi mod_len;
  size_t base_size;
  size_t exp_size;
  size_t mod_size;
  ret = read_lens(input_src, input_size,
                  &base_len, &exp_len, &mod_len,
                  &base_size, &exp_size, &mod_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }

  const uint8_t *content = input_size > 96 ? input_src + 96 : NULL;
  const size_t content_size = content != NULL ? input_size - 96 : 0;
  if (content_size < (base_size + exp_size + mod_size)) {
    return ERROR_MOD_EXP;
  }

  if (mbedtls_mpi_cmp_int(&base_len, 0) == 0 && mbedtls_mpi_cmp_int(&mod_len, 0) == 0) {
    *output = NULL;
    *output_size = 0;
    return 0;
  }

  mbedtls_mpi base;
  mbedtls_mpi exp;
  mbedtls_mpi mod;
  mbedtls_mpi result;
  mbedtls_mpi_init(&base);
  mbedtls_mpi_init(&exp);
  mbedtls_mpi_init(&mod);
  mbedtls_mpi_init(&result);
  ret = mbedtls_mpi_read_binary(&base, content, base_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_read_binary(&exp, content + base_size, exp_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_read_binary(&mod, content + base_size + exp_size, mod_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }

  *output = (uint8_t*)malloc(mod_size);
  *output_size = mod_size;
  if (mbedtls_mpi_bitlen(&mod) == 0) {
    memset(*output, 0, mod_size);
    return 0;
  }

  ret = mbedtls_mpi_exp_mod(&result, &base, &exp, &mod, NULL);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  ret = mbedtls_mpi_write_binary(&result, *output, mod_size);
  if (ret != 0) {
    return ERROR_MOD_EXP;
  }
  return 0;
}

static uint8_t precomputed[10][16] = {{0, 2, 4, 6, 1, 3, 5, 7, 8, 10, 12, 14, 9, 11, 13, 15},
                                      {14, 4, 9, 13, 10, 8, 15, 6, 1, 0, 11, 5, 12, 2, 7, 3},
                                      {11, 12, 5, 15, 8, 0, 2, 13, 10, 3, 7, 9, 14, 6, 1, 4},
                                      {7, 3, 13, 11, 9, 1, 12, 14, 2, 5, 4, 15, 6, 10, 0, 8},
                                      {9, 5, 2, 10, 0, 7, 4, 15, 14, 11, 6, 3, 1, 12, 8, 13},
                                      {2, 6, 0, 8, 12, 10, 11, 3, 4, 7, 15, 1, 13, 5, 14, 9},
                                      {12, 1, 14, 4, 5, 15, 13, 10, 0, 6, 9, 8, 7, 3, 2, 11},
                                      {13, 7, 12, 3, 11, 14, 1, 9, 5, 15, 8, 2, 0, 4, 6, 10},
                                      {6, 14, 11, 0, 15, 9, 3, 8, 12, 13, 1, 10, 2, 7, 4, 5},
                                      {10, 8, 7, 1, 2, 4, 6, 5, 15, 9, 3, 13, 11, 14, 12, 0},};
static uint64_t iv[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                          0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                          0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                          0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,};

int blake2f_required_gas(const uint8_t *input, const size_t input_size, uint64_t *target_gas) {
  if (input_size != BLAKE2F_INPUT_LENGTH) {
    *target_gas = 0;
    return 0;
  }
  uint32_t gas = ((uint32_t)input[0] << 24
                  | (uint32_t)input[1] << 16
                  | (uint32_t)input[2] << 8
                  | (uint32_t)input[3] << 0);
  *target_gas = (uint64_t)gas;
  return 0;
}

uint64_t rotate_left64(uint64_t x, int k) {
  size_t n = 64;
  size_t s = (size_t)(k) & (n - 1);
  return x<<s | x>>(n-s);
}

void f_generic(uint64_t h[8],
               uint64_t m[16],
               uint64_t c0,
               uint64_t c1,
               uint64_t flag,
               uint64_t rounds) {
  uint64_t v0 = h[0];
  uint64_t v1 = h[1];
  uint64_t v2 = h[2];
  uint64_t v3 = h[3];
  uint64_t v4 = h[4];
  uint64_t v5 = h[5];
  uint64_t v6 = h[6];
  uint64_t v7 = h[7];
  uint64_t v8 = iv[0];
  uint64_t v9 = iv[1];
  uint64_t v10 = iv[2];
  uint64_t v11 = iv[3];
  uint64_t v12 = iv[4];
  uint64_t v13 = iv[5];
  uint64_t v14 = iv[6];
  uint64_t v15 = iv[7];
	v12 ^= c0;
  v13 ^= c1;
  v14 ^= flag;

	for (uint64_t i = 0; i < rounds; i++)  {
		uint8_t *s = precomputed[i%10];

		v0 += m[s[0]];
		v0 += v4;
		v12 ^= v0;
		v12 = rotate_left64(v12, -32);
		v8 += v12;
		v4 ^= v8;
		v4 = rotate_left64(v4, -24);
		v1 += m[s[1]];
		v1 += v5;
		v13 ^= v1;
		v13 = rotate_left64(v13, -32);
		v9 += v13;
		v5 ^= v9;
		v5 = rotate_left64(v5, -24);
		v2 += m[s[2]];
		v2 += v6;
		v14 ^= v2;
		v14 = rotate_left64(v14, -32);
		v10 += v14;
		v6 ^= v10;
		v6 = rotate_left64(v6, -24);
		v3 += m[s[3]];
		v3 += v7;
		v15 ^= v3;
		v15 = rotate_left64(v15, -32);
		v11 += v15;
		v7 ^= v11;
		v7 = rotate_left64(v7, -24);

		v0 += m[s[4]];
		v0 += v4;
		v12 ^= v0;
		v12 = rotate_left64(v12, -16);
		v8 += v12;
		v4 ^= v8;
		v4 = rotate_left64(v4, -63);
		v1 += m[s[5]];
		v1 += v5;
		v13 ^= v1;
		v13 = rotate_left64(v13, -16);
    v9 += v13;
    v5 ^= v9;
    v5 = rotate_left64(v5, -63);
		v2 += m[s[6]];
		v2 += v6;
		v14 ^= v2;
		v14 = rotate_left64(v14, -16);
		v10 += v14;
		v6 ^= v10;
		v6 = rotate_left64(v6, -63);
		v3 += m[s[7]];
		v3 += v7;
		v15 ^= v3;
		v15 = rotate_left64(v15, -16);
		v11 += v15;
		v7 ^= v11;
		v7 = rotate_left64(v7, -63);

		v0 += m[s[8]];
		v0 += v5;
		v15 ^= v0;
		v15 = rotate_left64(v15, -32);
		v10 += v15;
		v5 ^= v10;
		v5 = rotate_left64(v5, -24);
		v1 += m[s[9]];
		v1 += v6;
		v12 ^= v1;
		v12 = rotate_left64(v12, -32);
		v11 += v12;
		v6 ^= v11;
		v6 = rotate_left64(v6, -24);
		v2 += m[s[10]];
		v2 += v7;
		v13 ^= v2;
		v13 = rotate_left64(v13, -32);
		v8 += v13;
		v7 ^= v8;
		v7 = rotate_left64(v7, -24);
		v3 += m[s[11]];
		v3 += v4;
		v14 ^= v3;
		v14 = rotate_left64(v14, -32);
		v9 += v14;
		v4 ^= v9;
		v4 = rotate_left64(v4, -24);

		v0 += m[s[12]];
		v0 += v5;
		v15 ^= v0;
		v15 = rotate_left64(v15, -16);
		v10 += v15;
		v5 ^= v10;
		v5 = rotate_left64(v5, -63);
		v1 += m[s[13]];
		v1 += v6;
		v12 ^= v1;
		v12 = rotate_left64(v12, -16);
		v11 += v12;
		v6 ^= v11;
		v6 = rotate_left64(v6, -63);
		v2 += m[s[14]];
		v2 += v7;
		v13 ^= v2;
		v13 = rotate_left64(v13, -16);
		v8 += v13;
		v7 ^= v8;
		v7 = rotate_left64(v7, -63);
		v3 += m[s[15]];
		v3 += v4;
		v14 ^= v3;
		v14 = rotate_left64(v14, -16);
		v9 += v14;
		v4 ^= v9;
		v4 = rotate_left64(v4, -63);
	}
	h[0] ^= v0 ^ v8;
	h[1] ^= v1 ^ v9;
	h[2] ^= v2 ^ v10;
	h[3] ^= v3 ^ v11;
	h[4] ^= v4 ^ v12;
	h[5] ^= v5 ^ v13;
	h[6] ^= v6 ^ v14;
	h[7] ^= v7 ^ v15;
}

int blake2f(gw_context_t *ctx,
              const uint8_t *input_src,
              const size_t input_size,
              uint8_t **output, size_t *output_size) {
  if (input_size != BLAKE2F_INPUT_LENGTH) {
    return ERROR_BLAKE2F;
  }
  if (input_src[212] != BLAKE2F_NON_FINAL_BLOCK_BYTES
      && input_src[212] != BLAKE2F_FINAL_BLOCK_BYTES) {
    return ERROR_BLAKE2F;
  }

  uint32_t rounds = ((uint32_t)input_src[0] << 24
                     | (uint32_t)input_src[1] << 16
                     | (uint32_t)input_src[2] << 8
                     | (uint32_t)input_src[3] << 0);
  bool final = input_src[212] == BLAKE2F_FINAL_BLOCK_BYTES;
  uint64_t h[8];
  uint64_t m[16];
  uint64_t t[2];
  for (size_t i = 0; i < 8; i++) {
    size_t offset = 4 + i * 8;
    h[i] = *(uint64_t *)(input_src + offset);
  }
  for (size_t i = 0; i < 16; i++) {
    size_t offset = 68 + i * 8;
    m[i] = *(uint64_t *)(input_src + offset);
  }
  t[0] = *(uint64_t *)(input_src + 196);
  t[1] = *(uint64_t *)(input_src + 204);

  uint64_t flag = final ? 0xFFFFFFFFFFFFFFFF : 0;
  f_generic(h, m, t[0], t[1], flag, (uint64_t)rounds);

  *output = (uint8_t *)malloc(64);
  *output_size = 64;
  for (size_t i = 0; i < 8; i++) {
    size_t offset = i * 8;
    memcpy(*output + offset, (uint8_t *)(&h[i]), 8);
  }
  return 0;
}

bool match_precompiled_address(const evmc_address *destination,
                            precompiled_contract_gas_fn *contract_gas,
                            precompiled_contract_fn *contract) {
  for (int i = 0; i < 19; i++) {
    if (destination->bytes[i] != 0) {
      return false;
    }
  }

  switch (destination->bytes[19]) {
  case 1:
    *contract_gas = ecrecover_required_gas;
    *contract = ecrecover;
    break;
  case 2:
    *contract_gas = sha256hash_required_gas;
    *contract = sha256hash;
    break;
  case 3:
    *contract_gas = ripemd160hash_required_gas;
    *contract = ripemd160hash;
    break;
  case 4:
    *contract_gas = data_copy_required_gas;
    *contract = data_copy;
    break;
  case 5:
    *contract_gas = big_mod_exp_required_gas;
    *contract = big_mod_exp;
    break;
    /* FIXME:
       common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
       common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
       common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
     */
  case 9:
    *contract_gas = blake2f_required_gas;
    *contract = blake2f;
    break;
  default:
    *contract_gas = NULL;
    *contract = NULL;
    return false;
  }
  return true;
}

#endif
