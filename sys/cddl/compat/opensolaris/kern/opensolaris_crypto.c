#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <sys/mbuf.h>
#include <crypto/rijndael/rijndael.h>
#include <sys/sun_ccm.h>
#include <sys/sun_gcm.h>
#include <crypto/sha2/sha2.h>
#include <sys/mbuf.h>


// ZFS_CRYPTO_VERBOSE is set in the crypto/api.h file
//#define ZFS_CRYPTO_VERBOSE

// EXTREF insists on having a rwlock. If not, it panics.
static u_int dummy = 0;


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

enum param_type_t {
    PARAM_TYPE_NONE = 0,
    PARAM_TYPE_CCM,
    PARAM_TYPE_GCM,
    PARAM_TYPE_CTR
};

struct cipher_map_s {
    enum cipher_type_t type;
    enum param_type_t param_type;
    char *solaris_name;

    void (*setkey)(rijndael_ctx *, uint8_t *, uint32_t);

    int (*enc)(rijndael_ctx *,
               struct mbuf *,
               struct mbuf *,
               uint64_t,
               uint8_t *,
               uint32_t,
               uint32_t);

    int (*dec)(rijndael_ctx *,
               struct mbuf *,
               struct mbuf *,
               uint64_t,
               uint8_t *,
               uint32_t,
               uint32_t);
};

typedef struct cipher_map_s cipher_map_t;

static cipher_map_t cipher_map[] =
{
    /* 0, not used, must be defined */
    { CIPHER_TYPE_MAC, PARAM_TYPE_NONE, "NULL Cipher", NULL, NULL, NULL },

    { CIPHER_TYPE_STREAM, PARAM_TYPE_CCM, "CKM_AES_CCM",
      sun_ccm_setkey, sun_ccm_encrypt_and_auth, sun_ccm_encrypt_and_auth },
    { CIPHER_TYPE_STREAM, PARAM_TYPE_GCM, "CKM_AES_GCM",
      sun_gcm_setkey, sun_gcm_encrypt_and_auth, sun_gcm_decrypt_and_auth },

    { CIPHER_TYPE_BLOCK, PARAM_TYPE_GCM, "CKM_AES_CTR",
      sun_gcm_setkey, sun_gcm_encrypt_and_auth, sun_gcm_decrypt_and_auth },

    { CIPHER_TYPE_MAC, PARAM_TYPE_NONE, "CKM_SHA256_HMAC_GENERAL",
      NULL, NULL, NULL },
};

#define NUM_CIPHER_MAP (sizeof(cipher_map) / sizeof(cipher_map_t))


/*
 * We do not need a free function with our mbufs, but MEXTADD panics if
 * given NULL. Please fix this FreeBSD.
 */
static void free_function(void *buf, void *arg)
{
    return;
}




/*
 * Map the Solaris RAW and UIO vector buffers, into FreeBSD mbuf (linked list)
 * Since FreeBSD does not have a kernel crypto API, this step is technically
 * not required, and we could process the buffers directly. But maybe one
 * day FreeBSD will add a proper API, where all ciphers take linked list of
 * buffers. (or similar clustered buffer lists)
 */
static size_t crypto_map_buffers(crypto_data_t *solaris_buffer,
                                 struct mbuf **m0)
{
    uio_t *uio = NULL;
    iovec_t *iov = NULL;
    struct mbuf *m, *prev = NULL;
    int total = 0;
    int i;

    *m0 = NULL;

    switch(solaris_buffer->cd_format) {
    case CRYPTO_DATA_RAW: // One buffer.
        // Only one buffer available, asking for any other is wrong
        MGET(m, M_WAITOK, MT_DATA);
        if (!m) return 0;

        m->m_ext.ref_cnt = &dummy;
        m->m_len = solaris_buffer->cd_length;
        // One would think MEXTADD would set m_len too..
        MEXTADD(m,
                solaris_buffer->cd_raw.iov_base,
                solaris_buffer->cd_length,
                free_function,
                NULL, NULL, 0, EXT_EXTREF);
#ifdef ZFS_CRYPTO_VERBOSE
        printf("crypto: mapping to %p (%04x)\n",
               mtod(m, void *), (uint32_t)m->m_len);
#endif
        *m0 = m;
        return m->m_len;

    case CRYPTO_DATA_UIO: // Multiple buffers.
        uio = solaris_buffer->cd_uio;
        iov = uio->uio_iov;

        for (i = 0;
             i < uio->uio_iovcnt;
             i++) {

            MGET(m, M_WAITOK, MT_DATA);
            if (!m) return 0;

            // If we have a previous, chain it.
            if (!*m0) *m0 = m;
            if (prev) prev->m_next = m;
            prev = m;

            m->m_ext.ref_cnt = &dummy;
            m->m_len = iov[i].iov_len;
            MEXTADD(m,
                    iov[i].iov_base,
                    iov[i].iov_len,
                    free_function,
                    NULL, NULL, 0, EXT_EXTREF);

#ifdef ZFS_CRYPTO_VERBOSE
            printf("crypto: mapping  %d to %p (%04x)\n",
                   i, mtod(m, void *), (uint32_t)m->m_len);
#endif

            total += m->m_len;
        } // for

        return total;

    case CRYPTO_DATA_MBLK: // network mbufs, not supported
    default:
        cmn_err(CE_PANIC, "spl-crypto: map->cd_format of unsupported type=%d",
                solaris_buffer->cd_format);
        return 0;
    } // switch cd_format
    return 0;
}


static int spl_crypto_map_iv(unsigned char *iv, int len,
                             crypto_mechanism_t *mech)
{
    cipher_map_t *cm = NULL;

    // Make sure we are to use iv
    if (!mech || !mech->cm_param || (len < 16)) goto clear;

    cm = &cipher_map[ mech->cm_type ];

    switch(cm->param_type) {

    case PARAM_TYPE_CCM:
        {
            CK_AES_CCM_PARAMS *ccm_param = (CK_AES_CCM_PARAMS *)mech->cm_param;
            if (!ccm_param || !ccm_param->nonce) goto clear;

            memcpy(iv, ccm_param->nonce, ccm_param->ulNonceSize);
            return ccm_param->ulNonceSize;

        }
        break;


    case PARAM_TYPE_GCM:
        {
            CK_AES_GCM_PARAMS *gcm_param = (CK_AES_GCM_PARAMS *)mech->cm_param;
            uint32_t ivlen;
            if (!gcm_param || !gcm_param->pIv) goto clear;

            /*
             * Unfortunately, the implementations between FreeBSD and
             * Linux differ in handling the case of GCM ivlen != 12.
             * So we force ivlen = 12 for now.
             */

            ivlen = gcm_param->ulIvLen;
            if (ivlen != 12) ivlen = 12;

            memset(iv, 0, len);
            memcpy(iv, gcm_param->pIv, MIN(gcm_param->ulIvLen, ivlen));

            return 12;
        }
        break;

    case PARAM_TYPE_CTR:
        {
            CK_AES_CTR_PARAMS *ctr_param = (CK_AES_CTR_PARAMS *)mech->cm_param;
            if (!ctr_param) goto clear;

            memset(iv, 0, sizeof(iv));
            memcpy(iv, ctr_param->cb, ctr_param->ulCounterBits >> 3);
            /* Linux crypto API does not let you change ivlen */
            //return ctr_param->ulCounterBits >> 3;
            return 16;
        }

    default:
        break;
    }

 clear:
    memset(iv, 0, len);
    return 0;
}


int crypto_mac(crypto_mechanism_t *mech, crypto_data_t *data,
               crypto_key_t *key, crypto_ctx_template_t tmpl,
               crypto_data_t *mac, crypto_call_req_t *cr)
{
    int ret = CRYPTO_FAILED;
    SHA256_CTX sha;
    u_int8_t digest[SHA256_DIGEST_LENGTH];
    struct mbuf *mdata  = NULL;
    struct mbuf *mmac  = NULL;
    size_t plainlen = 0, cryptlen = 0;

    // Setup the first buffer
    if (!(plainlen  = crypto_map_buffers(data,  &mdata)))
        goto out;
    if (!(cryptlen  = crypto_map_buffers(mac, &mmac)))
        goto out;

    SHA256_Init(&sha);
    while(mdata && plainlen) {
        SHA256_Update(&sha, mtod(mdata, uint8_t *), mdata->m_len);
        mdata = mdata->m_next;
    }
    SHA256_Final(digest, &sha);

    // FIXME, doesn't handle split digest buffer
    if (mmac && (mmac->m_len >= SHA256_DIGEST_LENGTH)) {
        memcpy(mtod(mmac, void *), digest, SHA256_DIGEST_LENGTH);
    }

    ret = CRYPTO_SUCCESS;

    m_freem(mdata);
    m_freem(mmac);

 out:
#ifdef ZFS_CRYPTO_VERBOSE
    printf("spl-crypto: mac returning %d\n", ret);
#endif
    return ret;
}






static int crypto_encrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *plaintext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *ciphertext,
                                 crypto_call_req_t *cr)
{
    struct mbuf *mplain  = NULL;
    struct mbuf *mcipher = NULL;
    size_t plainlen = 0, cryptlen = 0, maclen = 0;
    rijndael_ctx   cc_aes;
    int ret;
    cipher_map_t *cm = NULL;
    uint8_t iv[16];
    uint32_t ivlen = 0;

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt_stream: %04lx\n", plaintext->cd_length);
#endif

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Setup the first buffer
    if (!(plainlen  = crypto_map_buffers(plaintext,  &mplain)))
        goto out;
    if (!(cryptlen  = crypto_map_buffers(ciphertext, &mcipher)))
        goto out;

    maclen = cryptlen - plainlen;

    // in CTR mode, we have no authtag
    if (cm->param_type == PARAM_TYPE_CTR)
        maclen = 0;

    cm->setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ivlen = spl_crypto_map_iv(iv, sizeof(iv), mech);

    ret = cm->enc(&cc_aes,
                  mplain,
                  mcipher,
                  plainlen,
                  iv,
                  ivlen,
                  maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt_stream: result %d\n",
           ret);
#endif

    m_freem(mplain);
    m_freem(mcipher);

    if (!ret) return CRYPTO_SUCCESS;

 out:
    return CRYPTO_FAILED;
}



static int crypto_decrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *ciphertext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *plaintext,
                                 crypto_call_req_t *cr)
{
    struct mbuf *mplain  = NULL;
    struct mbuf *mcipher = NULL;
    size_t plainlen = 0, cryptlen = 0, maclen = 0;
    rijndael_ctx   cc_aes;
    int ret;
    uint8_t iv[16];
    uint32_t ivlen = 0;
    cipher_map_t *cm = NULL;

    ASSERT(mech != NULL);

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt_stream: %04lx\n", plaintext->cd_length);
#endif

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    if (!(cryptlen  = crypto_map_buffers(ciphertext, &mcipher)))
        goto out;

    if (!(plainlen  = crypto_map_buffers(plaintext,  &mplain)))
        goto out;

    maclen = cryptlen - plainlen;

    if (cm->param_type == PARAM_TYPE_CTR)
        maclen = 0;

    cm->setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ivlen = spl_crypto_map_iv(iv, sizeof(iv), mech);

    ret = cm->dec(&cc_aes,
                  mcipher,
                  mplain,
                  plainlen,
                  iv,
                  ivlen,
                  maclen);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt_stream: result %d\n",
           ret);
#endif

    m_freem(mplain);
    m_freem(mcipher);

    if (ret == EBADMSG) {
        cmn_err(CE_WARN, "crypto: decrypt verify failed.");
        return CRYPTO_INVALID_MAC;
    }

    if (!ret) return CRYPTO_SUCCESS;
 out:
    return CRYPTO_FAILED;
}


static int crypto_encrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *plaintext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *ciphertext,
                                crypto_call_req_t *cr)
{
    int ret;

    ret = crypto_encrypt_stream(mech, plaintext, key, tmpl,
                                ciphertext, cr);

    return ret;
}

static int crypto_decrypt_block(crypto_mechanism_t *mech,
                                crypto_data_t *ciphertext,
                                crypto_key_t *key, crypto_ctx_template_t tmpl,
                                crypto_data_t *plaintext,
                                crypto_call_req_t *cr)
{
    int ret;

    ret = crypto_decrypt_stream(mech, ciphertext, key, tmpl,
                                plaintext, cr);

    // No authtag used with plain CTR
    if (ret == EBADMSG) ret = CRYPTO_SUCCESS;

    return ret;
}



int crypto_encrypt(crypto_mechanism_t *mech, crypto_data_t *plaintext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *ciphertext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    switch(cm->type) {
    case CIPHER_TYPE_STREAM:
        return crypto_encrypt_stream(mech, plaintext, key, tmpl,
                                     ciphertext, cr);
    case CIPHER_TYPE_BLOCK:
        return crypto_encrypt_block(mech, plaintext, key, tmpl,
                                    ciphertext, cr);
    case CIPHER_TYPE_MAC:
        return crypto_mac(mech, plaintext, key, tmpl,
                          ciphertext, cr);
    }

    return CRYPTO_FAILED;
}

int crypto_decrypt(crypto_mechanism_t *mech, crypto_data_t *ciphertext,
                   crypto_key_t *key, crypto_ctx_template_t tmpl,
                   crypto_data_t *plaintext, crypto_call_req_t *cr)
{
    cipher_map_t *cm = NULL;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt\n");
#endif

    if (mech->cm_type >= NUM_CIPHER_MAP) return CRYPTO_FAILED;
    cm = &cipher_map[ mech->cm_type ];

    switch(cm->type) {
    case CIPHER_TYPE_STREAM:
        return crypto_decrypt_stream(mech, ciphertext, key, tmpl,
                                     plaintext, cr);

    case CIPHER_TYPE_BLOCK:
        return crypto_decrypt_block(mech, ciphertext, key, tmpl,
                                    plaintext, cr);
    case CIPHER_TYPE_MAC:
        return crypto_mac(mech, plaintext, key, tmpl,
                          ciphertext, cr);
    }

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

    for (i = 0; i < NUM_CIPHER_MAP; i++) {

        if (cipher_map[i].solaris_name &&
            !strcmp(cipher_map[i].solaris_name, name)) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("called crypto_mech2id '%s' (returning %d)\n",
                   name, i);
#endif

            return i; // Index into list.
        }
    } // for all cipher maps

    printf("spl-crypto: mac2id returning INVALID for '%s'\n", name);
    return CRYPTO_MECH_INVALID;
}





