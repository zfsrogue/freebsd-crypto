#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
#define ZFS_CRYPTO_VERBOSE



/*
 * FreeBSD cipher types, and the Solaris equivalent.
 *
 * This is an indexed structure. First entry is not used, since return
 * of zero is considered failure. First cipher match, returns "1", then
 * "1" is used to look up the cipher name, and optional hmac.
 *
 */

enum cipher_type_t {
    CIPHER_TYPE_STREAM = 0,
    CIPHER_TYPE_BLOCK,
    CIPHER_TYPE_MAC,
};

struct cipher_map_s {
    enum cipher_type_t type;
    char *solaris_name;
    int power_on_test; /* If 0, check cipher exists. Set to 1 after that */
    char *freebsd_name;
    char *hmac_name;   /* optional hmac if not part of linux_name */
};

typedef struct cipher_map_s cipher_map_t;

static cipher_map_t cipher_map[] =
{
    /* 0, not used, must be defined */
    { CIPHER_TYPE_MAC,  "NULL Cipher", 0, NULL, NULL },
#if 0
    // TODO, attempt to make the MAC be the same as Solaris
    { CIPHER_TYPE_STREAM, "CKM_AES_CCM", 0, "sun-ctr(aes)", "hmac(sha256)" },
#else
    { CIPHER_TYPE_STREAM, "CKM_AES_CCM", 0, "sun-ccm(aes)", NULL },
#endif
    { CIPHER_TYPE_STREAM, "CKM_AES_GCM", 0, "sun-gcm(aes)", NULL },
    { CIPHER_TYPE_BLOCK,  "CKM_AES_CTR", 0, "sun-ctr(aes)", NULL },
    { CIPHER_TYPE_MAC,  "CKM_SHA256_HMAC_GENERAL", 0, NULL, "hmac(sha256)" },
};

#define NUM_CIPHER_MAP (sizeof(cipher_map) / sizeof(cipher_map_t))




#if 0
void spl_crypto_map_iv(unsigned char *iv, int len, void *param)
{
    CK_AES_CCM_PARAMS *ccm_param = (CK_AES_CCM_PARAMS *)param;

    // Make sure we are to use iv
    if (!ccm_param || !ccm_param->nonce || !ccm_param->ulNonceSize) {
        memset(iv, 0, len);
        return;
    }

    // 'iv' is set as, from Solaris kernel sources;
    // In ZFS-crypt, the "nonceSize" is always 12.
    // q = (uint8_t)((15 - nonceSize) & 0xFF);
    // cb[0] = 0x07 & (q-1);
    // cb[1..12] = supplied nonce
    // cb[13..14] = 0
    // cb[15] = 1;
    memset(iv, 0, len); // Make all bytes 0 first.
    iv[0]  = 0x02;
    memcpy(&iv[1], ccm_param->nonce, ccm_param->ulNonceSize); // 12 bytes
    iv[15] = 0x01;

}
#endif



int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl, crypto_data_t *mac,
               crypto_call_req_t *cr)
{
    int ret = CRYPTO_FAILED;

#if _KERNEL
    printf("crypto_mac\n");
#endif

#ifdef ZFS_CRYPTO_VERBOSE
    printf("spl-crypto: mac returning %d\n", ret);
#endif
    return ret;
}

struct freebsd_uio {
    unsigned char *addr;
    size_t len;
    off_t offset;
    int uio_index;
};

typedef struct freebsd_uio fuio;


static void crypto_block_xor20(unsigned char *src, unsigned char *dst,
                               size_t len)
{
    int i;

    for (i = 0; i < len; i++) {
        dst[i] = src[i] ^ 0x20;
    }
}


/*
 * Attempt to map "the current" Solaris UIO vector buffer, into
 * the made-up FreeBSD struct "fuio".
 */
static int crypto_map_buffers(crypto_data_t *solaris_buffer, fuio *fbsd)
{
    uio_t *uio = NULL;
    iovec_t *iov = NULL;

    switch(solaris_buffer->cd_format) {
    case CRYPTO_DATA_RAW: // One buffer.
        // Only one buffer available, asking for any other is wrong
        if (fbsd->uio_index != 0) return 1;

        fbsd->addr   = solaris_buffer->cd_raw.iov_base;
        fbsd->len    = solaris_buffer->cd_length;
        fbsd->offset = 0;
        printf("crypto: mapping  %d to %p (%04lx)\n",
               fbsd->uio_index, fbsd->addr, fbsd->len);
        fbsd->uio_index++;
        return fbsd->len;

    case CRYPTO_DATA_UIO: // Multiple buffers.
        uio = solaris_buffer->cd_uio;
        iov = uio->uio_iov;
        // Make sure index is inside number of available buffers
        if (fbsd->uio_index >= uio->uio_iovcnt) return 0;

        fbsd->addr   = iov[fbsd->uio_index].iov_base;
        fbsd->len    = iov[fbsd->uio_index].iov_len;
        fbsd->offset = 0;
        printf("crypto: mapping+ %d to %p (%04lx)\n",
               fbsd->uio_index, fbsd->addr, fbsd->len);
        fbsd->uio_index++;
        return fbsd->len;

    case CRYPTO_DATA_MBLK: // network mbufs, not supported
    default:
        cmn_err(CE_PANIC, "spl-crypto: map->cd_format of unsupported type=%d",
                solaris_buffer->cd_format);
        return 0;
    } // switch cd_format
    return 0;
}



static int crypto_encrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *plaintext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *ciphertext,
                                 crypto_call_req_t *cr)
{
    //cipher_map_t *cm = NULL;
    fuio plainfuio;
    fuio cipherfuio;
    int maclen;
    size_t len_done;

#if _KERNEL
    printf("crypto_encrypt_stream: %04lx\n", plaintext->cd_length);
#endif

    // Set index to 0, to start from the beginning.
    plainfuio.uio_index = 0;
    cipherfuio.uio_index = 0;
    len_done = 0;

    // Setup the first buffer
    crypto_map_buffers(plaintext,  &plainfuio);
    crypto_map_buffers(ciphertext, &cipherfuio);

    // While we have INPUT length...
    while(len_done < plaintext->cd_length) {

        // Find which buffer is the smallest, this is the transfer size
        if (plainfuio.len <= cipherfuio.len) { // plain is smaller

            printf("crypto: plain (%04x) <= cipher(%04x)\n",
                   (unsigned int)plainfuio.len,
                   (unsigned int)cipherfuio.len);

            crypto_block_xor20(&plainfuio.addr[ plainfuio.offset ],
                               &cipherfuio.addr[ cipherfuio.offset ],
                               plainfuio.len);
            cipherfuio.offset += plainfuio.len;
            cipherfuio.len -= plainfuio.len;
            len_done += plainfuio.len;
            // Change plain to the next buffer, clears offset.
            if (!crypto_map_buffers(plaintext,  &plainfuio)) break;

        } else { // cipher is smaller

            printf("crypto: plain (%04x)  > cipher(%04x)\n",
                   (unsigned int)plainfuio.len,
                   (unsigned int)cipherfuio.len);

            crypto_block_xor20(&plainfuio.addr[ plainfuio.offset ],
                               &cipherfuio.addr[ cipherfuio.offset ],
                               cipherfuio.len);
            plainfuio.offset += cipherfuio.len;
            plainfuio.len -= cipherfuio.len;
            len_done += cipherfuio.len;
            // Change cipher to the next buffer, clears offset.
            if (!crypto_map_buffers(ciphertext,  &cipherfuio)) break;

        }

    }

    // mac
    maclen = ciphertext->cd_length - plaintext->cd_length;

    // Do mac, if separate buffer, set that up
    if (!cipherfuio.len) crypto_map_buffers(ciphertext,  &cipherfuio);

    // Compute mac
    memset(cipherfuio.addr, 0, MIN(maclen, cipherfuio.len));

    printf("crypto_encrypt_stream: done %04x: mac %d\n",
           (unsigned int)len_done, maclen);
    return CRYPTO_SUCCESS;
}

static int crypto_decrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *ciphertext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *plaintext,
                                 crypto_call_req_t *cr)
{
    //cipher_map_t *cm = NULL;
    fuio plainfuio;
    fuio cipherfuio;
    int maclen;
    size_t len_done;

#if _KERNEL
    printf("crypto_decrypt_stream: %04lx\n", ciphertext->cd_length);
#endif

    // Set index to 0, to start from the beginning.
    plainfuio.uio_index = 0;
    cipherfuio.uio_index = 0;
    len_done = 0;

    // Setup the first buffer
    crypto_map_buffers(plaintext,  &plainfuio);
    crypto_map_buffers(ciphertext, &cipherfuio);

    // While we have OUTPUT length... (cipher is bigger due to mac)
    while(len_done < plaintext->cd_length) {

        // Find which buffer is the smallest, this is the transfer size
        if (plainfuio.len <= cipherfuio.len) { // plain is smaller

            printf("crypto: plain (%04x) <= cipher(%04x)\n",
                   (unsigned int)plainfuio.len,
                   (unsigned int)cipherfuio.len);

            crypto_block_xor20(&cipherfuio.addr[ cipherfuio.offset ],
                               &plainfuio.addr[ plainfuio.offset ],
                               plainfuio.len);
            cipherfuio.offset += plainfuio.len;
            cipherfuio.len -= plainfuio.len;
            len_done += plainfuio.len;
            // Change plain to the next buffer, clears offset.
            if (!crypto_map_buffers(plaintext,  &plainfuio)) break;

        } else { // cipher is smaller

            printf("crypto: plain (%04x)  > cipher(%04x)\n",
                   (unsigned int)plainfuio.len,
                   (unsigned int)cipherfuio.len);

            crypto_block_xor20(&cipherfuio.addr[ cipherfuio.offset ],
                               &plainfuio.addr[ plainfuio.offset ],
                               cipherfuio.len);
            plainfuio.offset += cipherfuio.len;
            plainfuio.len -= cipherfuio.len;
            len_done += cipherfuio.len;
            // Change cipher to the next buffer, clears offset.
            if (!crypto_map_buffers(ciphertext,  &cipherfuio)) break;

        }

    }

    // mac
    maclen = ciphertext->cd_length - plaintext->cd_length;

    printf("crypto_decrypt_stream: done %04x: mac %d\n",
           (unsigned int)len_done, maclen);
    return CRYPTO_SUCCESS;
}


static int crypto_encrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *plaintext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *ciphertext,
                                crypto_call_req_t *cr)
{
    return CRYPTO_FAILED;
}

static int crypto_decrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *ciphertext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *plaintext,
                                crypto_call_req_t *cr)
{
    return CRYPTO_FAILED;
}



int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#if _KERNEL
    printf("crypto_encrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#if 1
    if (cm->type == CIPHER_TYPE_STREAM)
        return crypto_encrypt_stream(mech, plaintext, key, tmpl,
                                     ciphertext, cr);

    if (cm->type == CIPHER_TYPE_BLOCK)
        return crypto_encrypt_block(mech, plaintext, key, tmpl,
                                    ciphertext, cr);
#endif

    return CRYPTO_FAILED;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#if _KERNEL
    printf("crypto_decrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#if 1
    if (cm->type == CIPHER_TYPE_STREAM)
        return crypto_decrypt_stream(mech, ciphertext, key, tmpl,
                                     plaintext, cr);

    if (cm->type == CIPHER_TYPE_BLOCK)
        return crypto_decrypt_block(mech, ciphertext, key, tmpl,
                                    plaintext, cr);
#endif

    return CRYPTO_FAILED;
}





int crypto_create_ctx_template(crypto_mechanism_t *mech,
    crypto_key_t *key, crypto_ctx_template_t *tmpl, int kmflag)
{
    return 0;
}

void crypto_destroy_ctx_template(crypto_ctx_template_t tmpl)
{
    return;
}


/*
 *
 * This function maps between Solaris cipher string, and Linux cipher string.
 * It is always used as 'early test' on cipher availability, so we include
 * testing the cipher here.
 *
 */
crypto_mech_type_t crypto_mech2id(crypto_mech_name_t name)
{
    int i;

    if (!name || !*name)
        return CRYPTO_MECH_INVALID;

#ifdef ZFS_CRYPTO_VERBOSE
#if _KERNEL
    printf("called crypto_mech2id '%s' (total %d)\n", name, (int)NUM_CIPHER_MAP);
#endif
#endif

    for (i = 0; i < NUM_CIPHER_MAP; i++) {

        if (cipher_map[i].solaris_name &&
            !strcmp(cipher_map[i].solaris_name, name)) {

            // Do we test the cipher?
            if (!cipher_map[i].power_on_test) {

                // Test it only once
                cipher_map[i].power_on_test = 1;

                if (cipher_map[i].type == CIPHER_TYPE_STREAM) {

                } else if (cipher_map[i].type == CIPHER_TYPE_BLOCK) {

                } else if (cipher_map[i].type == CIPHER_TYPE_MAC) {

                } else {
                    return CRYPTO_MECH_INVALID;
                }

            }

            return i; // Index into list.
        }
    } // for all cipher maps

    printf("spl-crypto: mac2id returning INVALID\n");
    return CRYPTO_MECH_INVALID;
}





