/*-
 * Copyright 2013 Jorgen Lundman <lundman@lundman.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

/*
 *
 * Implement CTR-AES, 4byte nonce, 8byte iv, 4byte counter
 *
 * Implement GCM authtag, which uses magic somehow
 *
 * authtag is computed and put at the end of the output "cipher" buffer.
 *
 *
 */

//#define ZFS_CRYPTO_VERBOSE

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/misc.h>
#include <sys/module.h>

#include <sys/socket.h>

#include <sys/_rwlock.h>

#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/ethernet.h>
#include <crypto/rijndael/rijndael.h>

#include <sys/sun_gcm.h>
#include <sys/endian.h>


/*
 * Are we guaranteed that all xor operations are on 4 byte boundaries?
 */
static __inline void xor_block(uint8_t *dst,
                               uint8_t *src,
                               size_t size)
{
#if 1
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;

    for (; size >= 4; size -= 4)
        *a++ ^= *b++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
#endif
    for (; size; size--)
        *dst++ ^= *src++;
}

static __inline void xor_block2(uint8_t *dst,
                                uint8_t *src,
                                uint8_t *xor,
                                size_t size)
{
#if 1
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;
    uint32_t *x = (uint32_t *)xor;

    for (; size >= 4; size -= 4)
        *a++ = *b++ ^ *x++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
    xor = (uint8_t *)x;
#endif
    for (; size; size--)
        *dst++ = *src++ ^ *xor++;
}


#define CCMP_ENCRYPT(_i, _S, _b0, _pos, _out, _e, _len, _H) do {   \
        /* Encryption, with counter */                             \
        _b0[12] = (_i >> 24)& 0xff;                                \
        _b0[13] = (_i >> 16)& 0xff;                                \
        _b0[14] = (_i >> 8) & 0xff;                                \
        _b0[15] = _i & 0xff;                                       \
        rijndael_encrypt(cc_aes, _b0, _e);                         \
        xor_block2(_out, _pos, _e, _len);                          \
        /* Authentication */                                       \
        ghash(H, _out, _len, S);                                   \
} while (0)

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _out, _H, _len, _S) do {      \
        /* Authentication */                                          \
        ghash(_H, _pos, _len, _S);                                    \
        /* Decrypt, with counter */                                   \
        _b0[12] = (_i >> 24)& 0xff;                                   \
        _b0[13] = (_i >> 16)& 0xff;                                   \
        _b0[14] = (_i >> 8) & 0xff;                                   \
        _b0[15] = _i & 0xff;                                          \
        rijndael_encrypt(cc_aes, _b0, _b);                            \
        xor_block2(_out, _pos, _b, _len);                             \
} while (0)


/*
 * Advance to the next mbuf in a mbuf chain.
 */
#define M_NEXTBUFFER(D,S,P,L) do {     \
        (D)=(S);                       \
        if (D) {                       \
            (P)=mtod((D), uint8_t *);  \
            (L)=(D)->m_len;            \
        } else {                       \
            (P) = NULL;                \
            (L) = 0;                   \
        }                              \
    } while(0)




void sun_gcm_setkey(rijndael_ctx *cc_aes,
                    uint8_t *key, uint32_t keylen)
{
    rijndael_set_key(cc_aes, key, keylen*NBBY);
}


/*
 * For authtag;
 * B0 is computed with M and L in flags (first byte), then nonce is copied in
 * followed by the cryptlen at the end, with most significant byte first.
 */
static void ccm_init_b0(uint8_t *b0,
                        uint8_t *nonce,
                        uint32_t noncelen)
{

    if (nonce && noncelen)
        memcpy(&b0[0], nonce, noncelen);
    else
        memset(&b0[0], 0, 12);

    b0[12] = 0x00;
    b0[13] = 0x00;
    b0[14] = 0x00;
    b0[15] = 0x01;

}




static void shift_right_block(uint8_t *v)
{
    uint32_t val;
    uint32_t *r;

    //val = WPA_GET_BE32(v + 12);
    r = (uint32_t *)&v[12];
    val = be32toh(*r);
    val >>= 1;
    if (v[11] & 0x01)
        val |= 0x80000000;
    *r = htobe32(val);
    //    WPA_PUT_BE32(v + 12, val);

    //val = WPA_GET_BE32(v + 8);
    r = (uint32_t *)&v[8];
    val = be32toh(*r);
    val >>= 1;
    if (v[7] & 0x01)
        val |= 0x80000000;
    *r = htobe32(val);
    //WPA_PUT_BE32(v + 8, val);

    //val = WPA_GET_BE32(v + 4);
    r = (uint32_t *)&v[4];
    val = be32toh(*r);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    *r = htobe32(val);
    //WPA_PUT_BE32(v + 4, val);

    //val = WPA_GET_BE32(v);
    r = (uint32_t *)&v[0];
    val = be32toh(*r);
    val >>= 1;
    *r = htobe32(val);
    //    WPA_PUT_BE32(v, val);
}

#define BIT(n) (1 << (n))

/* Multiplication in GF(2^128) */
static void gf_mult(uint8_t *x, uint8_t *y, uint8_t *z)
{
    uint8_t v[16];
    int i, j;

    memset(z, 0, 16); /* Z_0 = 0^128 */
    memcpy(v, y, 16); /* V_0 = Y */

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & BIT(7 - j)) {
                /* Z_(i + 1) = Z_i XOR V_i */
                xor_block(z, v, 16);
            } else {
                /* Z_(i + 1) = Z_i */
            }

            if (v[15] & 0x01) {
                /* V_(i + 1) = (V_i >> 1) XOR R */
                shift_right_block(v);
                /* R = 11100001 || 0^120 */
                v[0] ^= 0xe1;
            } else {
                /* V_(i + 1) = V_i >> 1 */
                shift_right_block(v);
            }
        }
    }
}


static void ghash_start(uint8_t *y)
{
    /* Y_0 = 0^128 */
    memset(y, 0, 16);
}


static void ghash(uint8_t *h, uint8_t *x, size_t xlen, uint8_t *y)
{
    size_t m, i;
    uint8_t *xpos = x;
    uint8_t tmp[16];

    m = xlen / 16;

    for (i = 0; i < m; i++) {
        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_block(y, xpos, 16);
        xpos += 16;

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    if (x + xlen > xpos) {
        /* Add zero padded last block */
        size_t last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);

        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_block(y, tmp, 16);

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    /* Return Y_m */
}


static void aes_gcm_init_hash_subkey(rijndael_ctx *aes,
                                     uint8_t *H)
{

    /* Generate hash subkey H = AES_K(0^128) */
    memset(H, 0, AES_BLOCK_LEN);
    rijndael_encrypt(aes, H, H);

}


static void aes_gcm_prepare_j0(uint8_t *iv, size_t iv_len,
                               uint8_t *H, uint8_t *J0)
{
    uint8_t len_buf[16];
    uint64_t s;

    if (iv_len == 12) {
        /* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, AES_BLOCK_LEN - iv_len);
        J0[AES_BLOCK_LEN - 1] = 0x01;
    } else {
        /*
         * s = 128 * ceil(len(IV)/128) - len(IV)
         * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
         */
        ghash_start(J0);
        ghash(H, iv, iv_len, J0);
        s = 0;
        memcpy(&len_buf[0], &s, sizeof(s));
        s = htobe64(iv_len*8);
        memcpy(&len_buf[8], &s, sizeof(s));
        //WPA_PUT_BE64(len_buf, 0);
        //WPA_PUT_BE64(len_buf + 8, iv_len * 8);
        ghash(H, len_buf, sizeof(len_buf), J0);
    }
}





static void aes_gcm_final(rijndael_ctx *aes, uint32_t aad_len,
                          uint32_t crypt_len, uint8_t *H, uint8_t *S,
                          uint8_t *J0, uint8_t *tag)
{
    uint64_t s;
    uint8_t len_buf[16];

    s = htobe64(aad_len * 8);
    memcpy(&len_buf[0], &s, sizeof(s));
    //WPA_PUT_BE64(len_buf, aad_len * 8);
    s = htobe64(crypt_len * 8);
    memcpy(&len_buf[8], &s, sizeof(s));
    //WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H, len_buf, sizeof(len_buf), S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    //aes_gctr(aes, J0, S, sizeof(S), tag);
    rijndael_encrypt(aes, J0, tag);
    xor_block(tag, S, 16);
}








/*
 * Encrypt "plain" struct mbuf(s) into "cipher" struct mbuf(s).
 * If there is room, tack the auth at the end of "cipher".
 */
int sun_gcm_encrypt_and_auth(rijndael_ctx *cc_aes,
                             struct mbuf *plain,
                             struct mbuf *cipher,
                             uint64_t total_len,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint64_t len = total_len;
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], tag[AES_BLOCK_LEN], e[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    struct mbuf *m_plain;  // Current mbuf being worked on.
    struct mbuf *m_cipher;
    uint64_t remainder;
    uint64_t avail;
    uint8_t  H[AES_BLOCK_LEN];
    uint8_t  J0[AES_BLOCK_LEN];
    uint8_t  S[AES_BLOCK_LEN];

#ifdef ZFS_CRYPTO_VERBOSE
    printf("gcm_encrypt enter\n");
#endif

    memset(tag, 0, sizeof(tag));
    memset(e, 0, sizeof(e));

    /*
     * ***********************************************************
     * For encryption, copy iv over to B0
     */

    ccm_init_b0(b0, nonce, noncelen);


    /*
     * ***********************************************************
     * GHASH needs key setup
     */

    aes_gcm_init_hash_subkey(cc_aes, H);


    /*
     * ***********************************************************
     * For AUTH, setup J0 correctly.
     */

    aes_gcm_prepare_j0(nonce, noncelen, H, J0);

    ghash_start(S);
    //ghash(H, aad, aad_len, S);
    ghash(H, NULL, 0, S);


    /*
     * ***********************************************************
     */

    // Encrypt

    // Setup first buffers.
    M_NEXTBUFFER(m_plain,  plain, src, srclen);
    M_NEXTBUFFER(m_cipher, cipher, dst, dstlen);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("Before:\n");
    for (i = 0; i < 16; i++)
        printf("0x%02x ", src[i]);
    printf("\n");
#endif

    // Process all 16 blocks in the smallest of the two buffers
    while(len && m_plain && m_cipher) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("gcmp_encrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

#ifdef ZFS_CRYPTO_VERBOSE
        printf("encrypt: opting to process buffer size 0x%04x\n",
               (uint32_t)space);
#endif
        i = 1;
        while (space >= AES_BLOCK_LEN) {
            i++; // Linux has counter=2 for first encrypted block
            CCMP_ENCRYPT(i, S, b0, src, dst, e, AES_BLOCK_LEN, H);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
        }

        if (!len) break; // all finished.

        // One, or both, of src or dst may not be 16 byte aligned, so we need
        // to handle this special case.
        if (((srclen > 0) && (srclen < AES_BLOCK_LEN)) ||
            ((dstlen > 0) && (dstlen < AES_BLOCK_LEN))) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("src 0x%04x dst 0x%04x total 0x%04x\n",
                   (uint32_t)srclen, (uint32_t)dstlen, (uint32_t)len);
#endif

            remainder = srclen;
            // If src actually have more than 16, we only want 16.
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            // Copy what we have to temp
            memcpy(tmp, src, remainder);
            // Clear the rest, in case we don't have more
            memset(&tmp[remainder], 0, AES_BLOCK_LEN - remainder);

            src+=remainder;
            srclen-=remainder;
            len -= remainder;

            // Advance to next buffer, but only if srclen was smaller than 16
            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                M_NEXTBUFFER(m_plain, m_plain->m_next, src, srclen);
                if (!m_plain) break; //error
                // Copy over new bytes, you'd think there be 16 bytes there
                // but just in case there isn't ...
                avail = MIN(srclen, AES_BLOCK_LEN-remainder);
                memcpy(&tmp[remainder], src, avail);
                src += avail;
                srclen-=avail;
                remainder += avail;
                len -= avail;
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            i++;
            CCMP_ENCRYPT(i, S, b0, tmp, tmp, e, AES_BLOCK_LEN, H);

            // Now it is time to write it out, and make sure there is space.
            remainder = dstlen;
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            memcpy(dst, tmp, remainder);
            dst+=remainder;
            dstlen-=remainder;

            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
                if (!m_cipher) break; // error
                avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
                memcpy(dst, &tmp[remainder], avail);
                dst += avail;
                dstlen -= avail;
                remainder += avail;
            }

#ifdef ZFS_CRYPTO_VERBOSE
            printf("Half block finished\n");
            printf("src 0x%04x dst 0x%04x total 0x%04x\n",
                   (uint32_t)srclen, (uint32_t)dstlen, (uint32_t)len);
#endif
        }

        if (srclen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing src\n");
#endif
            if (m_plain) {
                M_NEXTBUFFER(m_plain, m_plain->m_next, src, srclen);
            }
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            if (m_cipher) {
                M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
            }
        }
    } // while total length processing


    // No authtag? just leave
    if (!authlen) return 0;

    /*
     * ***********************************************************
     * Compute final GCM authtag
     */

    aes_gcm_final(cc_aes, 0, total_len, H, S, J0, tag);


#ifdef ZFS_CRYPTO_VERBOSE
    printf("gcmp_auth output:\n");
    for (i = 0; i < GCM_AUTH_LEN; i++)
        printf("0x%02x ", tag[i]);
    printf("\n");
#endif

    // Do we need to advance buffer?
    if (!dstlen && m_cipher && m_cipher->m_next) {
        M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
    }

#ifdef ZFS_CRYPTO_VERBOSE
    printf("Copying over auth: 0x%04x\n", (uint32_t) dstlen);
#endif

    // We need to try to find space in output to write auth
    remainder = dstlen;
    if (remainder > GCM_AUTH_LEN) remainder=GCM_AUTH_LEN;

    memcpy(dst, tag, remainder);
    dst+=remainder;
    dstlen-=remainder;

    while((remainder < AES_BLOCK_LEN) && m_cipher) {

        // Advance input to next buffer
        M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
        if (!m_cipher) break; // error
        avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
        memcpy(dst, &tag[remainder], avail);
        dst += avail;
        remainder += avail;
    }
#ifdef ZFS_CRYPTO_VERBOSE
    printf("encryption completed.\n");
#endif

    return 0;
}

/*
 * Decrypt "cipher" struct mbuf(s) into "plain" struct mbuf(s).
 * authtag should follow after "cipher", is verified against computed auth.
 */
int sun_gcm_decrypt_and_auth(rijndael_ctx *cc_aes,
                             struct mbuf *cipher,
                             struct mbuf *plain,
                             uint64_t total_len,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint64_t len = total_len;
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], tag[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    struct mbuf *m_plain;  // Current mbuf being worked on.
    struct mbuf *m_cipher;
    uint64_t remainder;
    uint64_t avail;
    uint8_t  H[AES_BLOCK_LEN];
    uint8_t  J0[AES_BLOCK_LEN];
    uint8_t  S[AES_BLOCK_LEN];

    memset(b, 0, sizeof(b));
    memset(tag, 0, sizeof(tag));

    /*
     * ***********************************************************
     * For encryption, copy iv over to B0
     */

    ccm_init_b0(b0, nonce, noncelen);


    /*
     * ***********************************************************
     * GHASH needs key setup
     */

    aes_gcm_init_hash_subkey(cc_aes, H);

    /*
     * ***********************************************************
     * For AUTH, setup J0 correctly.
     */

    aes_gcm_prepare_j0(nonce, noncelen, H, J0);

    ghash_start(S);
    //ghash(H, aad, aad_len, S);
    ghash(H, NULL, 0, S);


    /*
     * ***********************************************************
     * Decrypt
     */

    // Setup first buffers.
    M_NEXTBUFFER(m_cipher, cipher, src, srclen);
    M_NEXTBUFFER(m_plain,  plain,  dst, dstlen);

    while(len && m_plain && m_cipher) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("gcmp_decrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

        i = 1;
        while (space >= AES_BLOCK_LEN) {
            i++;
            CCMP_DECRYPT(i, b, b0, src, dst, H, AES_BLOCK_LEN, S);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
        }

        if (!len) break; // All finished

        // One, or both, of src or dst may not be 16 byte aligned, so we need
        // to handle this special case.
        if (((srclen > 0) && (srclen < AES_BLOCK_LEN)) ||
            ((dstlen > 0) && (dstlen < AES_BLOCK_LEN))) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("src buffer has %d remaining bytes\n", (uint32_t)srclen);
            printf("dst buffer has %d remaining bytes\n", (uint32_t)dstlen);
#endif

            remainder = srclen;
            // If src actually have more than 16, we only want 16.
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            // Copy what we have to temp
            memcpy(tmp, src, remainder);
            // Clear the rest, incase we have no more input
            memset(&tmp[remainder], 0, AES_BLOCK_LEN-remainder);
            src+=remainder;
            srclen-=remainder;
            len -= remainder;

            // Advance to next buffer, but only if srclen was smaller than 16
            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                M_NEXTBUFFER(m_cipher, m_cipher->m_next, src, srclen);
                if (!m_cipher) break; //error
                // Copy over new bytes, you'd think there be 16 bytes there
                // but just in case there isn't ...
                avail = MIN(srclen, AES_BLOCK_LEN-remainder);
                memcpy(&tmp[remainder], src, avail);
                src += avail;
                srclen-=avail;
                remainder += avail;
                len -= avail;
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            i++;
            CCMP_DECRYPT(i, b, b0, tmp, tmp, H, AES_BLOCK_LEN, S);

            // Now it is time to write it out, and make sure there is space.
            remainder = dstlen;
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            memcpy(dst, tmp, remainder);
            dst+=remainder;
            dstlen-=remainder;

            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                M_NEXTBUFFER(m_plain, m_plain->m_next, dst, dstlen);
                if (!m_plain) break; // error
                avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
                memcpy(dst, &tmp[remainder], avail);
                dst += avail;
                dstlen-=avail;
                remainder += avail;
            }

#ifdef ZFS_CRYPTO_VERBOSE
            printf("Half block finished\n");
#endif
        }

        if (srclen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing src\n");
#endif
            if (m_cipher) {
                M_NEXTBUFFER(m_cipher, m_cipher->m_next, src, srclen);
            }
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            if (m_plain) {
                M_NEXTBUFFER(m_plain, m_plain->m_next, dst, dstlen);
            }
        }
    } // while total length processing


    // No authtag? just leave
    if (!authlen) return 0;


    /*
     * ***********************************************************
     * Compute final GCM authtag
     */

    aes_gcm_final(cc_aes, 0, total_len, H, S, J0, tag);


#ifdef ZFS_CRYPTO_VERBOSE
    printf("computed_auth output:\n");
    for (i = 0; i < GCM_AUTH_LEN; i++)
        printf("0x%02x ", tag[i]);
    printf("\n");

#endif

    // Do we need to advance buffer?
    if (!srclen && m_cipher && m_cipher->m_next) {
        M_NEXTBUFFER(m_cipher, m_cipher->m_next, src, srclen);
    }

    // We need to try to find the auth at end of input
    remainder = srclen;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("decryption completed, remaining in src 0x%04x\n",
           (uint32_t) remainder);
#endif

    if (remainder > GCM_AUTH_LEN) remainder=GCM_AUTH_LEN;

    memcpy(tmp, src, remainder);
    src+=remainder;
    srclen-=remainder;

    while((remainder < AES_BLOCK_LEN) && m_cipher) {

        // Advance input to next buffer
        M_NEXTBUFFER(m_cipher, m_cipher->m_next, src, srclen);
        if (!m_cipher) break; // error
        avail = MIN(srclen, AES_BLOCK_LEN-remainder);
        memcpy(&tmp[remainder], src, avail);
        src += avail;
        remainder += avail;
    }

#ifdef ZFS_CRYPTO_VERBOSE
    printf("end of src: remainder 0x%04x\n", (uint32_t)remainder);
    for (i = 0; i < remainder; i++)
        printf("0x%02x ", tmp[i]);
    printf("\n");
#endif

    if (memcmp(tmp, tag, remainder)) {
#ifdef ZFS_CRYPTO_VERBOSE
        printf("decrypt authtag mismatch\n");
#endif
        return EBADMSG;
    }
#ifdef ZFS_CRYPTO_VERBOSE
    printf("decrypt authtag is ggoooooddd\n");
#endif
    return 0;
}






