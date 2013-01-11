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
 * This source file was based on ieee80211_crypto_ccmp.c, which was not
 * generic enough to be of use.
 *
 * This implementation does not handle "Associated authentication data", and
 * assumes it is of length 0.
 *
 * authtag is computed and put at the end of the output "cipher" buffer.
 *
 * ZFS uses nonce of 12 bytes (length field is then 3 bytes). authtag of
 * 16 bytes.
 *
 */

#define ZFS_CRYPTO_VERBOSE

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

#include <sys/sun_ccm.h>

static __inline void xor_block(uint8_t *dst,
                               uint8_t *src,
                               size_t size)
{
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;

    for (; size >= 4; size -= 4)
        *a++ ^= *b++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
    for (; size; size--)
        *dst++ ^= *src++;
}

static __inline void xor_block2(uint8_t *dst,
                                uint8_t *src,
                                uint8_t *xor,
                                size_t size)
{
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;
    uint32_t *x = (uint32_t *)xor;

    for (; size >= 4; size -= 4)
        *a++ = *b++ ^ *x++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
    xor = (uint8_t *)x;
    for (; size; size--)
        *dst++ = *src++ ^ *xor++;
}


#define CCMP_ENCRYPT(_i, _b, _b0, _pos, _out, _e, _len) do { \
        /* Authentication */                            \
        xor_block(_b, _pos, _len);                      \
        rijndael_encrypt(cc_aes, _b, _b);               \
        /* Encryption, with counter */                  \
        _b0[14] = (_i >> 8) & 0xff;                     \
        _b0[15] = _i & 0xff;                            \
        rijndael_encrypt(cc_aes, _b0, _e);              \
        xor_block2(_out, _pos, _e, _len);               \
} while (0)

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _out, _a, _len) do { \
        /* Decrypt, with counter */                     \
        _b0[14] = (_i >> 8) & 0xff;                     \
        _b0[15] = _i & 0xff;                            \
        rijndael_encrypt(cc_aes, _b0, _b);              \
        xor_block2(_out, _pos, _b, _len);               \
        /* Authentication */                            \
        xor_block(_a, _out, _len);                      \
        rijndael_encrypt(cc_aes, _a, _a);               \
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




void sun_ccm_setkey(rijndael_ctx *cc_aes,
                    uint8_t *key, uint32_t keylen)
{
    rijndael_set_key(cc_aes, key, keylen*NBBY);
}


/*
 * Encrypt "plain" struct mbuf(s) into "cipher" struct mbuf(s).
 * If there is room, tack the auth at the end of "cipher".
 */
int sun_ccm_encrypt_and_auth(rijndael_ctx *cc_aes,
                             struct mbuf *plain,
                             struct mbuf *cipher,
                             uint64_t len,
                             uint8_t *nonce, uint32_t noncelen)
{
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], t[AES_BLOCK_LEN], e[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    uint8_t flags;
    struct mbuf *m_plain;  // Current mbuf being worked on.
    struct mbuf *m_cipher;
    uint64_t remainder;
    uint64_t avail;

    memset(t, 0, sizeof(t));
    memset(e, 0, sizeof(e));

    /*
     * ***********************************************************
     * For AUTH, setup b0 correctly.
     */

    // Compute M' from M
    flags = (CCM_AUTH_LEN-2)/2;  // M' = ((M-2)/2)
    flags &= 7;  // 3 bits only
    flags <<= 3; // Bits 5.4.3

    // Compute L' is number of bytes in the length field, minus one.
    // So, 3 bytes, makes L' be 2.
    flags |= (( 15-noncelen-1 )&7);

    b0[0] = flags;

    memcpy(&b0[1], nonce, noncelen);
    // Put the srclen into the sizelen number of bytes, if nonce is 12
    // 0    1 .... noncelen   length ... 15
    // 0    1 .... 12             13 ... 15
    for (i = noncelen+1, space = len;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = (uint8_t) (space & 0xff);
        space = space >> 8;
    }

    // Let's start, setup round 0
    rijndael_encrypt(cc_aes, b0, t);

    /*
     * ***********************************************************
     */

    // Setup b0 for encryption, flags&=7, counter=0.
    b0[0] &= 0x07;
    for (i = noncelen+1;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = 0;
    }

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
        printf("ccmp_encrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

#ifdef ZFS_CRYPTO_VERBOSE
        printf("encrypt: opting to process buffer size 0x%04x\n",
               (uint32_t)space);
#endif
        i = 1;
        while (space >= AES_BLOCK_LEN) {
            CCMP_ENCRYPT(i, t, b0, src, dst, e, AES_BLOCK_LEN);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
            i++;
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
            src+=remainder;
            srclen-=remainder;

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
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            CCMP_ENCRYPT(i, t, b0, tmp, tmp, e, AES_BLOCK_LEN);
            i++;
            len -= AES_BLOCK_LEN;

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
            M_NEXTBUFFER(m_plain, m_plain->m_next, src, srclen);
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
        }
    } // while total length processing


    /*
     * ***********************************************************
     */

    /*
     * Note: rfc 3610 and NIST 800-38C require counter of
	 * zero to encrypt auth tag.
	 */
    //b0[0] &= 0x07;
    for (i = noncelen+1;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = 0;
    }

    // To compute authentication value U, we use
    //  S_0 := E( K, A_0 ), where A_0 has flags&7, and counter = 0;
    //    U := T XOR first-M-bytes( S_0 )
    rijndael_encrypt(cc_aes, b0, b0);  // Get S_0
    xor_block(t, b0, AES_BLOCK_LEN);   // S_0 XOR T -> U

#ifdef ZFS_CRYPTO_VERBOSE
    printf("ccmp_auth output:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", t[i]);
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
    if (remainder > CCM_AUTH_LEN) remainder=CCM_AUTH_LEN;

    memcpy(dst, t, remainder);
    dst+=remainder;
    dstlen-=remainder;

    while((remainder < AES_BLOCK_LEN) && m_cipher) {

        // Advance input to next buffer
        M_NEXTBUFFER(m_cipher, m_cipher->m_next, dst, dstlen);
        if (!m_cipher) break; // error
        avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
        memcpy(dst, &t[remainder], avail);
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
int sun_ccm_decrypt_and_auth(rijndael_ctx *cc_aes,
                             struct mbuf *cipher,
                             struct mbuf *plain,
                             uint64_t len,
                             uint8_t *nonce, uint32_t noncelen)
{
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], a[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    uint8_t flags;
    struct mbuf *m_plain;  // Current mbuf being worked on.
    struct mbuf *m_cipher;
    uint64_t remainder;
    uint64_t avail;

    memset(b, 0, sizeof(b));
    memset(a, 0, sizeof(a));

    /*
     * ***********************************************************
     * For AUTH, setup b0 correctly -> "a"
     */

    // Compute M' from M
    flags = (CCM_AUTH_LEN-2)/2;  // M' = ((M-2)/2)
    flags &= 7;  // 3 bits only
    flags <<= 3; // Bits 5.4.3

    // Compute L' is number of bytes in the length field, minus one.
    // So, 3 bytes, makes L' be 2.
    flags |= (( 15-noncelen-1 )&7);

    b0[0] = flags;

    memcpy(&b0[1], nonce, noncelen);
    // Put the srclen into the sizelen number of bytes, if nonce is 12
    // 0    1 .... noncelen   length ... 15
    // 0    1 .... 12             13 ... 15
    for (i = noncelen+1, space = len;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = (uint8_t) (space & 0xff);
        space = space >> 8;
    }

    // Let's start, setup round 0
    rijndael_encrypt(cc_aes, b0, a);


    /*
     * ***********************************************************
     * Clear b0 flags and counter for decrypt
     */

    b0[0] &= 0x07;
    for (i = noncelen+1;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = 0;
    }


    /*
     * ***********************************************************
     * Decrypt
     */

    // Setup first buffers.
    M_NEXTBUFFER(m_cipher, cipher, src, srclen);
    M_NEXTBUFFER(m_plain,  plain,  dst, dstlen);

    while(len && m_plain && m_cipher) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("ccmp_decrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

        i = 1;
        while (space >= AES_BLOCK_LEN) {
            CCMP_DECRYPT(i, b, b0, src, dst, a, AES_BLOCK_LEN);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
            i++;
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
            src+=remainder;
            srclen-=remainder;

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
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            CCMP_DECRYPT(i, b, b0, tmp, tmp, a, AES_BLOCK_LEN);
            i++;
            len -= AES_BLOCK_LEN;

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
            M_NEXTBUFFER(m_cipher, m_cipher->m_next, src, srclen);
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            M_NEXTBUFFER(m_plain, m_plain->m_next, dst, dstlen);
        }
    } // while total length processing


    /*
     * ***********************************************************
     * Compute a->t->T->U and compare auth.
     */

    /*
     * Note: rfc 3610 and NIST 800-38C require counter of
	 * zero to encrypt auth tag.
	 */
    for (i = noncelen+1;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = 0;
    }

    // To compute authentication value U, we use
    //  S_0 := E( K, A_0 ), where A_0 has flags&7, and counter = 0;
    //    U := T XOR first-M-bytes( S_0 )
    rijndael_encrypt(cc_aes, b0, b0);  // Get S_0
    xor_block(a, b0, AES_BLOCK_LEN);   // S_0 XOR T -> U

#ifdef ZFS_CRYPTO_VERBOSE
    printf("computed_auth output:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", a[i]);
    printf("\n");

    printf("bug? srclen 0x%04x cipher at %p and next %p\n",
           (uint32_t) srclen, m_cipher, m_cipher ? m_cipher->m_next : NULL);
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

    if (remainder > CCM_AUTH_LEN) remainder=CCM_AUTH_LEN;

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

    if (memcmp(tmp, a, remainder)) {
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






