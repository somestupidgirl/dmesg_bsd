/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
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
 *	@(#)kvm_private.h	8.1 (Berkeley) 6/4/93
 */

#include <db.h>

#include "linker_set.h"
#include "endian.h"

typedef __int64_t kssize_t;
typedef struct segment_command_64 macho_shdr_t;

struct kvm_arch {
    int         (*ka_probe)(kvm_t *);
    int         (*ka_initvtop)(kvm_t *);
    void        (*ka_freevtop)(kvm_t *);
    int         (*ka_kvatop)(kvm_t *, kvaddr_t, off_t *);
    int         (*ka_native)(kvm_t *);
    int         (*ka_walk_pages)(kvm_t *, kvm_walk_pages_cb_t *, void *);
    kssize_t    (*ka_kerndisp)(kvm_t *);
};

#include "linker_set.h"

#define KVM_ARCH(ka)    DATA_SET(kvm_arch, ka)

#define roundup2(x, y)   ((((x)+((y)-1))/(y))*(y))   /* to any y */
#define rounddown2(x, y) ((x) & (~((y)-1))) /* if y is power of two */

#define __bitcount64(x) __builtin_popcountll((__uint64_t)(x))

struct __kvm {
    struct kvm_arch   *arch;
	/*
	 * a string to be prepended to error messages
	 * provided for compatibility with sun's interface
	 * if this value is null, errors are saved in errbuf[]
	 */
	const char        *program;
	char              *errp;		/* XXX this can probably go away */
	char               errbuf[_POSIX2_LINE_MAX];
    DB                *db;
#define ISALIVE(kd) ((kd)->vmfd >= 0)
	int	               pmfd;		/* physical memory file (or crashdump) */
	int	               vmfd;		/* virtual memory file (-1 if crashdump) */
	int	               swfd;		/* swap file (e.g., /dev/drum) */
	int	               nlfd;		/* namelist file (e.g., /vmunix) */
    macho_shdr_t       shdr;   /* ELF file header for namelist file */
    int (*resolve_symbol)(const char *, kvaddr_t *);
	struct kinfo_proc *procbase;
	char              *argspc;	/* (dynamic) storage for argv strings */
	int	               arglen;		/* length of the above */
	char             **argv;		/* (dynamic) storage for argv pointers */
	int	               argc;		/* length of above (not actual # present) */
	/*
	 * Kernel virtual address translation state.  This only gets filled
	 * in for dead kernels; otherwise, the running kernel (i.e. kmem)
	 * will do the translations for us.  It could be big, so we
	 * only allocate it if necessary.
	 */
	struct vmstate    *vmst;
    int                rawdump;    /* raw dump format */
    int                writable;   /* physical memory is writable */

    int                vnet_initialized;   /* vnet fields set up */
    kvaddr_t           vnet_start; /* start of kernel's vnet region */
    kvaddr_t           vnet_stop;  /* stop of kernel's vnet region */
    kvaddr_t           vnet_current;   /* vnet we're working with */
    kvaddr_t           vnet_base;  /* vnet base of current vnet */

    /*
     * Dynamic per-CPU kernel memory.  We translate symbols, on-demand,
     * to the data associated with dpcpu_curcpu, set with
     * kvm_dpcpu_setcpu().
     */
    int                 dpcpu_initialized;  /* dpcpu fields set up */
    kvaddr_t            dpcpu_start;    /* start of kernel's dpcpu region */
    kvaddr_t            dpcpu_stop; /* stop of kernel's dpcpu region */
    u_int               dpcpu_maxcpus;  /* size of base array */
    uintptr_t          *dpcpu_off; /* base array, indexed by CPU ID */
    u_int               dpcpu_curcpu;   /* CPU we're currently working with */
    kvaddr_t            dpcpu_curoff;   /* dpcpu base of current CPU */

    /* Page table lookup structures. */
    uint64_t           *pt_map;
    size_t              pt_map_size;
    uint64_t           *dump_avail;    /* actually word sized */
    size_t              dump_avail_size;
    off_t               pt_sparse_off;
    uint64_t            pt_sparse_size;
    uint32_t           *pt_popcounts;
    unsigned int        pt_page_size;

    /* Page & sparse map structures. */
    void               *page_map;
    uint32_t            page_map_size;
    off_t               page_map_off;
    void               *sparse_map;
};

struct kvm_bitmap {
    uint8_t *map;
    u_long size;
};

/* Page table lookup constants. */
#define POPCOUNT_BITS   1024
#define BITS_IN(v)  (sizeof(v) * NBBY)
#define POPCOUNTS_IN(v) (POPCOUNT_BITS / BITS_IN(v))

/*
 * The following structure is found at the top of the user stack of each
 * user process. The ps program uses it to locate argv and environment
 * strings. Programs that wish ps to display other information may modify
 * it; normally ps_argvstr points to the text for argv[0], and ps_nargvstr
 * is the same as the program's argc. The fields ps_envstr and ps_nenvstr
 * are the equivalent for the environment.
 */
struct ps_strings {
	char          *ps_argvstr;	/* first of 0 or more argument strings */
	int	           ps_nargvstr;	/* the number of argument strings */
	char          *ps_envstr;	/* first of 0 or more environment strings */
	int	           ps_nenvstr;	/* the number of environment strings */
};

/*
 * Functions used internally by kvm, but across kvm modules.
 */
static inline uint16_t
_kvm16toh(kvm_t *kd, uint16_t val)
{
    return (be16toh(val));
}

static inline uint32_t
_kvm32toh(kvm_t *kd, uint32_t val)
{
    return (be32toh(val));
}

static inline uint64_t
_kvm64toh(kvm_t *kd, uint64_t val)
{
    return (be64toh(val));
}

uint64_t _kvm_pa_bit_id(kvm_t *kd, uint64_t pa, unsigned int page_size);
uint64_t _kvm_bit_id_pa(kvm_t *kd, uint64_t bit_id, unsigned int page_size);
#define _KVM_PA_INVALID     ULONG_MAX
#define _KVM_BIT_ID_INVALID ULONG_MAX

int  _kvm_bitmap_init(struct kvm_bitmap *, u_long, u_long *);
void     _kvm_bitmap_set(struct kvm_bitmap *, u_long);
int  _kvm_bitmap_next(struct kvm_bitmap *, u_long *);
void     _kvm_bitmap_deinit(struct kvm_bitmap *);

void     _kvm_err(kvm_t *kd, const char *program, const char *fmt, ...)
        __printflike(3, 4);
void     _kvm_freeprocs(kvm_t *kd);
void    *_kvm_malloc(kvm_t *kd, size_t);
int  _kvm_nlist(kvm_t *, struct kvm_nlist *, int);
void    *_kvm_realloc(kvm_t *kd, void *, size_t);
void     _kvm_syserr (kvm_t *kd, const char *program, const char *fmt, ...)
        __printflike(3, 4);
int  _kvm_vnet_selectpid(kvm_t *, pid_t);
int  _kvm_vnet_initialized(kvm_t *, int);
kvaddr_t _kvm_vnet_validaddr(kvm_t *, kvaddr_t);
int  _kvm_dpcpu_initialized(kvm_t *, int);
kvaddr_t _kvm_dpcpu_validaddr(kvm_t *, kvaddr_t);
int  _kvm_probe_mach_kernel(kvm_t *, int, int);
int  _kvm_is_minidump(kvm_t *);
int  _kvm_pt_init(kvm_t *, size_t, off_t, size_t, off_t, off_t, int);
off_t    _kvm_pt_find(kvm_t *, uint64_t, unsigned int);
int  _kvm_visit_cb(kvm_t *, kvm_walk_pages_cb_t *, void *, u_long,
        u_long, u_long, vm_prot_t, size_t, unsigned int);
int  _kvm_pmap_init(kvm_t *, uint32_t, off_t);
void *   _kvm_pmap_get(kvm_t *, u_long, size_t);
void *   _kvm_map_get(kvm_t *, u_long, unsigned int);
int   _kvm_uvatop __P((kvm_t *, const struct proc *, u_long, u_long *));
