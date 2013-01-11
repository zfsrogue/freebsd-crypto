/*-
 * Copyright 2007 John Birrell <jb@FreeBSD.org>
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

cpu_core_t	cpu_core[MAXCPU];
kmutex_t	cpu_lock;
solaris_cpu_t	solaris_cpu[MAXCPU];
int		nsec_per_tick;

/*
 * We do not need a free function with our mbufs, but MEXTADD panics if
 * given NULL. Please fix this FreeBSD.
 */
static void free_function(void *buf, void *arg)
{
    return;
}




#define CRYPT_SIZE 0x2000


static void test_cipher(void)
{
    unsigned char key[16] = {
        0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
        0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97
    };
    unsigned char *src;
    unsigned char *dst;
    struct mbuf *msrc = NULL;
    struct mbuf *mdst = NULL;
    struct mbuf *t = NULL;
    struct mbuf *s = NULL;
    struct mbuf *mmac = NULL;
    int i;
    //struct ieee80211_key *wk;
    //struct ieee80211vap *vap = NULL;
    u_int dummy = 0;
    rijndael_ctx   cc_aes;
    uint8_t mac[CCM_AUTH_LEN];
    uint8_t nonce[12];

    printf("cipher test: \n");
    t = t;
    s = s;

    src = malloc(CRYPT_SIZE, M_TEMP, M_WAITOK);
    if (!src) return;

    dst = malloc(CRYPT_SIZE, M_TEMP, M_WAITOK);
    if (!dst) return;

    printf("buffer init.. \n");

    // Init src buffer, clear dst buffer
    for (i = 0; i < CRYPT_SIZE; i++) {
        src[i] = i;
    }
    memset(dst, 0, CRYPT_SIZE);

    // Set nonce to A7 and up, for 12 bytes.
    for (i = 0; i < 12; i++)
        nonce[i] = 0xa8+i;

    printf("mbufs.. \n");

    // create mbufs
    printf("m_get\n");
    //msrc = m_get(M_WAITOK, MT_DATA);

#if 1 // ONE SRC
    MGET(msrc, M_WAITOK, MT_DATA);
    if (!msrc) return;

    printf("mextadd\n");

    msrc->m_ext.ref_cnt = &dummy;
    msrc->m_len = CRYPT_SIZE;
    MEXTADD(msrc, src, CRYPT_SIZE, free_function,
            NULL, NULL, 0, EXT_EXTREF);

#else // SRC SPLIT IN TWO

#define SSPLIT 0x0ff3
    printf("Splitting src into two buffers at 0x%08x, plus mac\n",
           SSPLIT);

    MGET(msrc, M_WAITOK, MT_DATA);
    if (!msrc) return;

    msrc->m_ext.ref_cnt = &dummy;
    msrc->m_len = SSPLIT;
    MEXTADD(msrc, src, SSPLIT, free_function,
            NULL, NULL, 0, EXT_EXTREF);

    MGET(s, M_WAITOK, MT_DATA);
    if (!s) return;

    s->m_ext.ref_cnt = &dummy;
    s->m_len = CRYPT_SIZE-SSPLIT;
    MEXTADD(s, &src[SSPLIT], CRYPT_SIZE-SSPLIT, free_function,
            NULL, NULL, 0, EXT_EXTREF);

    msrc->m_next = s;

#endif

    printf("mnextadd.. \n");

#if 1 // ONE DST

    MGET(mdst, M_WAITOK, MT_DATA);
    if (!mdst) return;
    mdst->m_ext.ref_cnt = &dummy;
    mdst->m_len = CRYPT_SIZE;
    MEXTADD(mdst, dst, CRYPT_SIZE, free_function,
            NULL, NULL, 0, EXT_EXTREF);

    MGET(mmac, M_WAITOK, MT_DATA);
    mmac->m_ext.ref_cnt = &dummy;
    mmac->m_len = 12;
    MEXTADD(mmac, mac, 12, free_function,
            NULL, NULL, 0, EXT_EXTREF);
    mdst->m_next = mmac;

#else // DST SPLIT IN TWO

#define SPLIT 0x1007
    printf("Splitting dst into two buffers at 0x%08x, plus mac\n",
           SPLIT);

    MGET(mdst, M_WAITOK, MT_DATA);
    if (!mdst) return;
    mdst->m_ext.ref_cnt = &dummy;
    mdst->m_len = SPLIT;
    MEXTADD(mdst, &dst[0], SPLIT, free_function,
            NULL, NULL, 0, EXT_EXTREF);

    MGET(t, M_WAITOK, MT_DATA);
    if (!t) return;
    t->m_ext.ref_cnt = &dummy;
    t->m_len = CRYPT_SIZE-SPLIT;
    MEXTADD(t, &dst[SPLIT], CRYPT_SIZE-SPLIT, free_function,
            NULL, NULL, 0, EXT_EXTREF);
    mdst->m_next = t;

    MGET(mmac, M_WAITOK, MT_DATA);
    mmac->m_ext.ref_cnt = &dummy;
    mmac->m_len = 12;
    MEXTADD(mmac, mac, 12, free_function,
            NULL, NULL, 0, EXT_EXTREF);
    t->m_next = mmac;

    printf("mmac next is %p\n", mmac->m_next);
#endif

    // Call cipher
    printf("cipher init.. \n");

    sun_ccm_setkey(&cc_aes, key, sizeof(key));

    i = sun_ccm_encrypt_and_auth(&cc_aes, msrc, mdst, CRYPT_SIZE,
                                 nonce, sizeof(nonce));

    printf("encrypt say %d\n", i);

    printf("decrypt test\n");

    i = sun_ccm_decrypt_and_auth(&cc_aes, mdst, msrc, CRYPT_SIZE,
                                 nonce, sizeof(nonce));

    printf("decrypt say %d\n", i);

    printf("whats in plain:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", src[i]);
    printf("\n");

    printf("whats in mmac mac:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", mac[i]);
    printf("\n");

    m_freem(msrc);
    m_freem(mdst);

}




/*
 *  OpenSolaris subsystem initialisation.
 */
static void
opensolaris_load(void *dummy)
{
	int i;

	/*
	 * "Enable" all CPUs even though they may not exist just so
	 * that the asserts work. On FreeBSD, if a CPU exists, it is
	 * enabled.
	 */
	for (i = 0; i < MAXCPU; i++) {
		solaris_cpu[i].cpuid = i;
		solaris_cpu[i].cpu_flags &= CPU_ENABLE;
	}

	mutex_init(&cpu_lock, "OpenSolaris CPU lock", MUTEX_DEFAULT, NULL);

	nsec_per_tick = NANOSEC / hz;

    printf("cipher test start\n");
    test_cipher();
    printf("cipher test done\n");
}

SYSINIT(opensolaris_register, SI_SUB_OPENSOLARIS, SI_ORDER_FIRST, opensolaris_load, NULL);

static void
opensolaris_unload(void)
{
	mutex_destroy(&cpu_lock);
}

SYSUNINIT(opensolaris_unregister, SI_SUB_OPENSOLARIS, SI_ORDER_FIRST, opensolaris_unload, NULL);

static int
opensolaris_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		utsname.nodename = prison0.pr_hostname;
		break;

	case MOD_UNLOAD:
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;

	}
	return (error);
}

DEV_MODULE(opensolaris, opensolaris_modevent, NULL);
MODULE_VERSION(opensolaris, 1);
