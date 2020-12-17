/* Polyjuice validator */

#include "ckb_syscalls.h"
#include "common.h"
#include "gw_def.h"
#include "gw_smt.h"
#include "validator/validator.h"
#include "generator/polyjuice.h"

int sys_load(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
             uint8_t value[GW_VALUE_BYTES]) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  if (gw_ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_account_key(account_id, key, raw_key);
  return syscall(GW_SYS_LOAD, raw_key, value, 0, 0, 0, 0);
}
int sys_store(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
              const uint8_t value[GW_VALUE_BYTES]) {
  gw_context_t *gw_ctx = (gw_context_t *)ctx;
  if (gw_ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  uint8_t raw_key[GW_KEY_BYTES];
  gw_build_account_key(account_id, key, raw_key);
  return syscall(GW_SYS_STORE, raw_key, value, 0, 0, 0, 0);
}

int sys_load_nonce(void *ctx, uint32_t account_id, uint8_t value[GW_VALUE_BYTES]) {
  uint8_t key[32];
  gw_build_nonce_key(account_id, key);
  return syscall(GW_SYS_LOAD, key, value, 0, 0, 0, 0);
}

/* set call return data */
int sys_set_program_return_data(void *ctx, uint8_t *data, uint32_t len) {
  return syscall(GW_SYS_SET_RETURN_DATA, data, len, 0, 0, 0, 0);
}

/* Get account id by account script_hash */
int sys_get_account_id_by_script_hash(void *ctx, uint8_t script_hash[32],
                                      uint32_t *account_id) {
  return syscall(GW_SYS_LOAD_ACCOUNT_ID_BY_SCRIPT_HASH, script_hash, account_id,
                 0, 0, 0, 0);
}

/* Get account script_hash by account id */
int sys_get_script_hash_by_account_id(void *ctx, uint32_t account_id,
                                      uint8_t script_hash[32]) {
  return syscall(GW_SYS_LOAD_SCRIPT_HASH_BY_ACCOUNT_ID, account_id, script_hash,
                 0, 0, 0, 0);
}

/* Get account script by account id */
int sys_get_account_script(void *ctx, uint32_t account_id, uint32_t *len,
                         uint32_t offset, uint8_t *script) {
  return syscall(GW_SYS_LOAD_ACCOUNT_SCRIPT, account_id, len, offset, script, 0, 0);
}
/* Store data by data hash */
int sys_store_data(void *ctx,
                 uint32_t data_len,
                 uint8_t *data) {
  return syscall(GW_SYS_STORE_DATA, data_len, data, 0, 0, 0, 0);
}
/* Load data by data hash */
int sys_load_data(void *ctx, uint8_t data_hash[32],
                 uint32_t *len, uint32_t offset, uint8_t *data) {
  return syscall(GW_SYS_LOAD_DATA, data_hash, len, offset, data, 0, 0);
}

int _sys_load_l2transaction(void *addr, uint64_t *len) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_TRANSACTION, addr, &inner_len, 0, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int _sys_load_block_info(void *addr, uint64_t *len) {
  volatile uint64_t inner_len = *len;
  int ret = syscall(GW_SYS_LOAD_BLOCKINFO, addr, &inner_len, 0, 0, 0, 0);
  *len = inner_len;
  return ret;
}

int sys_create(void *ctx, uint8_t *script, uint32_t script_len,
               uint32_t *account_id) {
  return syscall(GW_SYS_CREATE, script, script_len, account_id, 0, 0, 0);
}

int sys_log(void *ctx, uint32_t account_id, uint32_t data_length,
            const uint8_t *data) {
  return syscall(GW_SYS_LOG, account_id, data_length, data, 0, 0, 0);
}

int main() {
  return 0;
}
