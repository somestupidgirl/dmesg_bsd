/*
 * Copyright (c) 1999-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 *
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <libproc.h>
#include <limits.h>
#include <locale.h>
#include <nlist.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include <sys/types.h>
#include <sys/msgbuf.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>

#define MSGBUF_SEQ_TO_POS(mbp, seq) ((seq) % (mbp)->msg_size)

static struct nlist nl[] = {
#define X_MSGBUF    0
    { "_msgbufp", 0, 0, 0, 0 },
    { NULL, 0, 0, 0, 0 },
};

#define KREAD(addr, var) \
    kvm_read(kd, addr, &var, sizeof(var)) != sizeof(var)

static void
usage(void)
{
    fprintf(stderr, "usage: dmesg [-a] [-M core [-N system]]\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    struct msgbuf *bufp, cur;
	char *msgbuf = NULL;
    char *visbuf, *ep, *memf, *nextp, *nlistf, *p, *q;
    kvm_t *kd;
	int ch;
    int msgbufsize = 0;
    size_t bufpos;
	size_t sysctlsize = sizeof(msgbufsize);
	long pri, data_size;
    bool all;

    all = false;
    (void) setlocale(LC_CTYPE, "");

    memf = nlistf = NULL;

    while ((ch = getopt(argc, argv, "acM:N:h:")) != -1)
        switch(ch) {
        case 'a':
            all = true;
            break;
        case 'M':
            memf = optarg;
            break;
        case 'N':
            nlistf = optarg;
            break;
        case '?':
        default:
            usage();
        }

    argc -= optind;
	if (argc > 1) {
		usage();
    }

    if (memf == NULL) {
    	if (sysctlbyname("kern.msgbuf", &msgbufsize, &sysctlsize, NULL, 0)) {
    		perror("Unable to size kernel buffer");
    	}

        /* Allocate extra room for growth between the sysctl calls. */
        msgbufsize += msgbufsize/8;
        /* Allocate more than sysctl sees, for room to append \n\0. */
        if ((msgbuf = malloc(msgbufsize + 2)) == NULL) {
            errx(1, "malloc failed");
        }

    	if (msgbuf == NULL) {
    		perror("Unable to allocate a message buffer");
    	}

        if (msgbufsize > 0 && msgbuf[msgbufsize - 1] == '\0') {
            msgbuf--;
        }

    	if ((data_size = proc_kmsgbuf(msgbuf, msgbufsize)) == 0){
    		perror("Unable to obtain kernel buffer");
    		usage();
    	}
    } else {
        /* Read in kernel message buffer and do sanity checks. */
        kd = kvm_open(nlistf, memf, NULL, O_RDONLY, "dmesg");
        if (kd == NULL)
            exit (1);
        if (kvm_nlist(kd, nl) == -1)
            errx(1, "kvm_nlist: %s", kvm_geterr(kd));
        if (nl[X_MSGBUF].n_type == 0)
            errx(1, "%s: msgbufp not found",
                nlistf ? nlistf : "namelist");
        if (KREAD(nl[X_MSGBUF].n_value, bufp) || KREAD((long)bufp, cur))
            errx(1, "kvm_read: %s", kvm_geterr(kd));
        if (cur.msg_magic != MSG_MAGIC)
            errx(1, "kernel message buffer has different magic "
                "number");
        if ((msgbuf = malloc(cur.msg_size + 2)) == NULL)
            errx(1, "malloc failed");

        /* Unwrap the circular buffer to start from the oldest data. */
        bufpos = MSGBUF_SEQ_TO_POS(&cur, cur.msg_bufx);
        if (kvm_read(kd, (long)&cur.msg_bufc[bufpos], msgbuf,
            cur.msg_size - bufpos) != (ssize_t)(cur.msg_size - bufpos))
            errx(1, "kvm_read: %s", kvm_geterr(kd));
        if (bufpos != 0 && kvm_read(kd, (long)cur.msg_bufc,
            &msgbuf[cur.msg_size - bufpos], bufpos) != (ssize_t)bufpos)
            errx(1, "kvm_read: %s", kvm_geterr(kd));
        kvm_close(kd);
        msgbufsize = cur.msg_size;
    }

    /*
     * Ensure that the buffer ends with a newline and a \0 to avoid
     * complications below.  We left space above.
     */
    if (msgbufsize == 0 || msgbuf[msgbufsize - 1] != '\n') {
        msgbuf[msgbufsize++] = '\n';
    }
    msgbuf[msgbufsize] = '\0';

    if ((visbuf = malloc(4 * msgbufsize + 1)) == NULL) {
        errx(1, "malloc failed");
    }

        /*
     * The message buffer is circular, but has been unwrapped so that
     * the oldest data comes first.  The data will be preceded by \0's
     * if the message buffer was not full.
     */
    p = msgbuf;
    ep = &msgbuf[msgbufsize];
    if (*p == '\0') {
        /* Strip leading \0's */
        p = memchr(p, '\n', ep - p);
        p++;
    }
    for (; p < ep; p = nextp) {
        nextp = memchr(p, '\n', ep - p);
        nextp++;

        /* Skip ^<[0-9]+> syslog sequences. */
        if (*p == '<' && isdigit(*(p+1))) {
            errno = 0;
            pri = strtol(p + 1, &q, 10);

            if (*q == '>' && pri >= 0 && pri < INT_MAX && errno == 0) {
                if (LOG_FAC(pri) != LOG_KERN && !all)
                    continue;
                p = q + 1;
            }
        }

        (void)strvisx(visbuf, p, nextp - p, 0);
        (void)printf("%s", visbuf);
    }
	visbuf = malloc(data_size*4);
	strvis(visbuf, msgbuf, 0);
	printf("%s", visbuf);
	free(visbuf);
	exit(0);
}
