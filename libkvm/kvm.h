/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *	@(#)kvm.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _KVM_H_
#define	_KVM_H_

#include <nlist.h>
#include <mach/vm_prot.h>
#include <mach/vm_types.h>
#include <sys/types.h>

/* Default version symbol. */
#define	VRS_SYM		"_version"
#define	VRS_KEY		"VERSION"

typedef uint64_t kpaddr_t;
typedef uint64_t kvaddr_t;

struct kvm_nlist {
    const char *n_name;
    unsigned char n_type;
    kvaddr_t n_value;
};

struct kvm_page {
    u_int       kp_version;
    kpaddr_t    kp_paddr;
    kvaddr_t    kp_kmap_vaddr;
    kvaddr_t    kp_dmap_vaddr;
    vm_prot_t   kp_prot;
    off_t       kp_offset;
    size_t      kp_len;
    /* end of version 2 */
};

__BEGIN_DECLS

typedef struct __kvm kvm_t;

struct kinfo_proc;
int kvm_close(kvm_t *);
char **kvm_getargv(kvm_t *, const struct kinfo_proc *, int);
char **kvm_getenvv(kvm_t *, const struct kinfo_proc *, int);
char *kvm_geterr(kvm_t *);
int	kvm_getloadavg(kvm_t *, double [], int);
char *kvm_getfiles(kvm_t *, int, int, int *);
struct kinfo_proc *kvm_getprocs(kvm_t *, int, int, int *);
int kvm_nlist(kvm_t *kd, struct nlist *nl);
kvm_t *kvm_openfiles(const char *uf, const char *mf, const char *sf __unused, int flag, char *errout);
kvm_t *kvm_open(const char *uf, const char *mf, const char *sf __unused, int flag, const char *errstr);
ssize_t kvm_read(kvm_t *kd, u_long kva, void *buf, size_t len);
ssize_t kvm_read2(kvm_t *kd, kvaddr_t kva, void *buf, size_t len);
ssize_t kvm_write(kvm_t *kd, u_long kva, const void *buf, size_t len);

typedef int kvm_walk_pages_cb_t(struct kvm_page *, void *);
int kvm_walk_pages(kvm_t *, kvm_walk_pages_cb_t *, void *);

__END_DECLS

#endif /* !_KVM_H_ */
