#include <sys/crypto/api.h>
#include <sys/cmn_err.h>

#include <sys/mbuf.h>
#include <crypto/rijndael/rijndael.h>
#include <sys/sun_ccm.h>


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


/*
 * We do not need a free function with our mbufs, but MEXTADD panics if
 * given NULL. Please fix this FreeBSD.
 */
static void free_function(void *buf, void *arg)
{
    return;
}




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



static int crypto_encrypt_stream(crypto_mechanism_t *mech,
                                 crypto_data_t *plaintext,
                                 crypto_key_t *key, crypto_ctx_template_t tmpl,
                                 crypto_data_t *ciphertext,
                                 crypto_call_req_t *cr)
{
    struct mbuf *mplain  = NULL;
    struct mbuf *mcipher = NULL;
    size_t plainlen = 0, cryptlen = 0;
    rijndael_ctx   cc_aes;
    int ret;
    CK_AES_CCM_PARAMS *ccm_param;

    ASSERT(mech != NULL);

    ccm_param = (CK_AES_CCM_PARAMS *)mech->cm_param;
    ASSERT(ccm_param != NULL);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_encrypt_stream: %04lx\n", plaintext->cd_length);
#endif

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    // Setup the first buffer
    if (!(plainlen  = crypto_map_buffers(plaintext,  &mplain)))
        goto out;
    if (!(cryptlen  = crypto_map_buffers(ciphertext, &mcipher)))
        goto out;

    sun_ccm_setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ret = sun_ccm_encrypt_and_auth(&cc_aes,
                                   mplain,
                                   mcipher,
                                   plainlen,
                                   ccm_param->nonce,
                                   ccm_param->ulNonceSize);

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
    size_t plainlen = 0, cryptlen = 0;
    rijndael_ctx   cc_aes;
    int ret;
    CK_AES_CCM_PARAMS *ccm_param;

    ASSERT(mech != NULL);

    ccm_param = (CK_AES_CCM_PARAMS *)mech->cm_param;
    ASSERT(ccm_param != NULL);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("crypto_decrypt_stream: %04lx\n", plaintext->cd_length);
#endif

    ASSERT(key->ck_format == CRYPTO_KEY_RAW);

    if (!(cryptlen  = crypto_map_buffers(ciphertext, &mcipher)))
        goto out;

    if (!(plainlen  = crypto_map_buffers(plaintext,  &mplain)))
        goto out;

    sun_ccm_setkey(&cc_aes, key->ck_data, key->ck_length / 8);

    ret = sun_ccm_decrypt_and_auth(&cc_aes,
                                   mcipher,
                                   mplain,
                                   plainlen,
                                   ccm_param->nonce,
                                   ccm_param->ulNonceSize);

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

#ifdef ZFS_CRYPTO_VERBOSE
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

#ifdef ZFS_CRYPTO_VERBOSE
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
    printf("called crypto_mech2id '%s' (total %d)\n", name, (int)NUM_CIPHER_MAP);
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





