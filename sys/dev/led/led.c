/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@FreeBSD.org> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/ctype.h>
#include <sys/sbuf.h>
#include <sys/queue.h>
#include <dev/led/led.h>
#include <sys/uio.h>

struct ledsc {
	LIST_ENTRY(ledsc)	list;
	void			*private;
	led_t			*func;
	dev_t			dev;
	struct sbuf		*spec;
	char			*str;
	char			*ptr;
	int			count;
};

static unsigned next_minor;
static struct mtx led_mtx;
static LIST_HEAD(, ledsc) led_list = LIST_HEAD_INITIALIZER(&led_list);

MALLOC_DEFINE(M_LED, "LED", "LED driver");

static void
led_timeout(void *p)
{
	struct ledsc	*sc;

	mtx_lock(&led_mtx);
	LIST_FOREACH(sc, &led_list, list) {
		if (sc->ptr == NULL)
			continue;
		if (sc->count > 0) {
			sc->count--;
			continue;
		}
		if (*sc->ptr == '.') {
			sc->ptr = NULL;
			continue;
		} else if (*sc->ptr >= 'a' && *sc->ptr <= 'j') {
			sc->func(sc->private, 0);
		} else if (*sc->ptr >= 'A' && *sc->ptr <= 'J') {
			sc->func(sc->private, 1);
		}
		sc->count = *sc->ptr & 0xf;
		sc->ptr++;
		if (*sc->ptr == '\0')
			sc->ptr = sc->str;
	}
	mtx_unlock(&led_mtx);
	timeout(led_timeout, p, hz / 10);
	return;
}

static int
led_write(dev_t dev, struct uio *uio, int ioflag)
{
	int error;
	char *s, *s2;
	struct ledsc *sc;
	struct sbuf *sb;
	struct sbuf *sb2;
	int i;

	sc = dev->si_drv1;

	if (uio->uio_resid > 512)
		return (EINVAL);
	s2 = s = malloc(uio->uio_resid + 1, M_DEVBUF, M_WAITOK);
	if (s == NULL)
		return (ENOMEM);
	s[uio->uio_resid] = '\0';
	error = uiomove(s, uio->uio_resid, uio);
	if (error) {
		free(s2, M_DEVBUF);
		return (error);
	}

	/*
	 * Handle "on" and "off" immediately so people can flash really
	 * fast from userland if they want to
	 */
	if (*s == '0' || *s == '1') {
		mtx_lock(&led_mtx);
		sb2 = sc->spec;
		sc->spec = NULL;
		sc->str = NULL;
		sc->ptr = NULL;
		sc->count = 0;
		sc->func(sc->private, *s & 1);
		mtx_unlock(&led_mtx);
		if (sb2 != NULL)
			sbuf_delete(sb2);
		free(s2, M_DEVBUF);
		return(0);
	}

	sb = sbuf_new(NULL, NULL, 0, SBUF_AUTOEXTEND);
	if (sb == NULL) {
		free(s2, M_DEVBUF);
		return (ENOMEM);
	}
		
	switch(s[0]) {
		/*
		 * Flash, default is 100msec/100msec.
		 * 'f2' sets 200msec/200msec etc.
		 */
		case 'f':
			if (s[1] >= '1' && s[1] <= '9')
				i = s[1] - '1';
			else
				i = 0;
			sbuf_printf(sb, "%c%c", 'A' + i, 'a' + i);
			break;
		/*
		 * Digits, flashes out numbers.
		 * 'd12' becomes -__________-_-______________________________
		 */
		case 'd':
			for(s++; *s; s++) {
				if (!isdigit(*s))
					continue;
				i = *s - '0';
				if (i == 0)
					i = 10;
				for (; i > 1; i--) 
					sbuf_cat(sb, "Aa");
				sbuf_cat(sb, "Aj");
			}
			sbuf_cat(sb, "jj");
			break;
		/*
		 * String, roll your own.
		 * 'a-j' gives "off" for n/10 sec.
		 * 'A-J' gives "on" for n/10 sec.
		 * no delay before repeat
		 * 'sAaAbBa' becomes _-_--__-
		 */
		case 's':
			for(s++; *s; s++) {
				if ((*s >= 'a' && *s <= 'j') ||
				    (*s >= 'A' && *s <= 'J') ||
					*s == '.')
					sbuf_bcat(sb, s, 1);
			}
			break;
		/*
		 * Morse.
		 * '.' becomes _-
		 * '-' becomes _---
		 * ' ' becomes __
		 * '\n' becomes ____
		 * 1sec pause between repeats
		 * '... --- ...' -> _-_-_-___---_---_---___-_-_-__________
		 */
		case 'm':
			for(s++; *s; s++) {
				if (*s == '.')
					sbuf_cat(sb, "aA");
				else if (*s == '-')
					sbuf_cat(sb, "aC");
				else if (*s == ' ')
					sbuf_cat(sb, "b");
				else if (*s == '\n')
					sbuf_cat(sb, "d");
			}
			sbuf_cat(sb, "j");
			break;
		default:
			sbuf_delete(sb);
			free(s2, M_DEVBUF);
			return (EINVAL);
	}
	sbuf_finish(sb);
	free(s2, M_DEVBUF);
	if (sbuf_overflowed(sb)) {
		sbuf_delete(sb);
		return (ENOMEM);
	}
	if (sbuf_len(sb) == 0) {
		sbuf_delete(sb);
		return (0);
	}

	mtx_lock(&led_mtx);
	sb2 = sc->spec;
	sc->spec = sb;
	sc->str = sbuf_data(sb);
	sc->ptr = sc->str;
	sc->count = 0;
	mtx_unlock(&led_mtx);
	if (sb2 != NULL)
		sbuf_delete(sb2);
	return(0);
}

static struct cdevsw led_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_NEEDGIANT,
	.d_write =	led_write,
	.d_name =	"LED",
};

dev_t
led_create(led_t *func, void *priv, char const *name)
{
	struct ledsc	*sc;
	struct sbuf *sb;

	if (next_minor == 0) {
		mtx_init(&led_mtx, "LED mtx", NULL, MTX_DEF);
		timeout(led_timeout, NULL, hz / 10);
	}

	sb = sbuf_new(NULL, NULL, SPECNAMELEN, SBUF_FIXEDLEN);
	if (sb == NULL)
		return (NODEV);
	sbuf_cpy(sb, "led/");
	sbuf_cat(sb, name);
	sbuf_finish(sb);
	if (sbuf_overflowed(sb)) {
		sbuf_delete(sb);
		return (NODEV);
	}
		
	sc = malloc(sizeof *sc, M_LED, M_WAITOK | M_ZERO);
	sc->private = priv;
	sc->func = func;
	sc->dev = make_dev(&led_cdevsw, unit2minor(next_minor),
	    UID_ROOT, GID_WHEEL, 0600, sbuf_data(sb));
	sc->dev->si_drv1 = sc;
	next_minor++;
	sbuf_delete(sb);
	mtx_lock(&led_mtx);
	LIST_INSERT_HEAD(&led_list, sc, list);
	sc->func(sc->private, 0);
	mtx_unlock(&led_mtx);
	return (sc->dev);
}

void
led_destroy(dev_t dev)
{
	struct ledsc *sc;

	sc = dev->si_drv1;
	mtx_lock(&led_mtx);
	LIST_REMOVE(sc, list);
	mtx_unlock(&led_mtx);
	if (sc->spec != NULL)
		sbuf_delete(sc->spec);
	destroy_dev(dev);
	free(sc, M_LED);
}
