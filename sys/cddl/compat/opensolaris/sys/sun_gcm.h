#ifndef SUN_GCM_H
#define SUN_GCM_H


#define AES_BLOCK_LEN 16
#define GCM_AUTH_LEN 16

void sun_gcm_setkey(rijndael_ctx *cc_aes,
                    uint8_t *key, uint32_t keylen);

int  sun_gcm_decrypt_and_auth(rijndael_ctx *cc_aes,
                              struct mbuf *cipher,
                              struct mbuf *plain,
                              uint64_t total_len,
                              uint8_t *nonce, uint32_t noncelen,
                              uint32_t authlen);

int  sun_gcm_encrypt_and_auth(rijndael_ctx *cc_aes,
                              struct mbuf *plain,
                              struct mbuf *cipher,
                              uint64_t total_len,
                              uint8_t *nonce, uint32_t noncelen,
                              uint32_t authlen);

#endif
