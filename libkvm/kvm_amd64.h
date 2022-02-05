/*-
 * Copyright (c) 2015 John H. Baldwin <jhb@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __KVM_AMD64_H__
#define	__KVM_AMD64_H__

#ifdef __amd64__
#include <mach/i386/vm_param.h>
#include <sys/vm.h>
#endif

typedef uint64_t	amd64_physaddr_t;
typedef uint64_t	amd64_pte_t;
typedef uint64_t	amd64_pde_t;
typedef uint64_t	amd64_pdpe_t;
typedef	uint64_t	amd64_pml4e_t;

#define	AMD64_NPTEPG		(AMD64_PAGE_SIZE / sizeof(amd64_pte_t))
#define	AMD64_PAGE_SHIFT	12
#define	AMD64_PAGE_SIZE		(1 << AMD64_PAGE_SHIFT)
#define	AMD64_PAGE_MASK		(AMD64_PAGE_SIZE - 1)
#define	AMD64_NPDEPG		(AMD64_PAGE_SIZE / sizeof(amd64_pde_t))
#define	AMD64_PDRSHIFT		21
#define	AMD64_NBPDR		    (1ULL << AMD64_PDRSHIFT)
#define	AMD64_PDRMASK		(AMD64_NBPDR - 1)
#define	AMD64_NPDPEPG		(AMD64_PAGE_SIZE / sizeof(amd64_pdpe_t))
#define	AMD64_PDPSHIFT		30
#define	AMD64_NBPDP		    (1ULL << AMD64_PDPSHIFT)
#define	AMD64_PDPMASK		(AMD64_NBPDP - 1)
#define	AMD64_NPML4EPG		(AMD64_PAGE_SIZE / sizeof(amd64_pml4e_t))
#define	AMD64_PML4SHIFT		39

#define	AMD64_PG_NX		    (1ULL << 63)
#define	AMD64_PG_V		    (0x001)
#define	AMD64_PG_RW		    (0x002)
#define	AMD64_PG_PS		    (0x080)
#define	AMD64_PG_FRAME		(0x000ffffffffff000ULL)
#define	AMD64_PG_PS_FRAME	(0x000fffffffe00000ULL)
#define	AMD64_PG_1GB_FRAME	(0x000fffffc0000000ULL)

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#define PAGE_SIZE               4096
#endif
#ifdef PAGE_SHIFT
#undef PAGE_SHIFT
#define PAGE_SHIFT              12
#endif
#ifdef PAGE_MASK
#undef PAGE_MASK
#define PAGE_MASK               (PAGE_SIZE - 1)
#endif

typedef uint64_t                pt_entry_t;
#define NPTEPG                  (PAGE_SIZE/(sizeof (pt_entry_t)))

typedef uint64_t                pd_entry_t;
#define NPDEPG                  (PAGE_SIZE/(sizeof (pd_entry_t)))
#define PDSHIFT                 21
#define NBPD                    (1ULL << PDSHIFT)
#define PDMASK                  (NBPD-1)

typedef uint64_t                pml4_entry_t;
#define NPML4EPG                (PAGE_SIZE/(sizeof (pml4_entry_t)))
#define PML4SHIFT               39

#define PDPTSHIFT               30
#define NBPDPT                  (1ULL << PDPTSHIFT)
#define PDPTMASK                (NBPDPT - 1)

#define PG_V                    (0x001)
#define PG_PS                   (0x080)
#define PG_FRAME                (0x000ffffffffff000ULL)
#define PG_PS_FRAME             (0x000fffffffe00000ULL)

#ifdef __amd64__
_Static_assert(NPTEPG == AMD64_NPTEPG, "NPTEPG mismatch");
_Static_assert(PAGE_SHIFT == AMD64_PAGE_SHIFT, "PAGE_SHIFT mismatch");
_Static_assert(PAGE_SIZE == AMD64_PAGE_SIZE, "PAGE_SIZE mismatch");
_Static_assert(PAGE_MASK == AMD64_PAGE_MASK, "PAGE_MASK mismatch");
_Static_assert(NPDEPG == AMD64_NPDEPG, "NPDEPG mismatch");
_Static_assert(PDSHIFT == AMD64_PDRSHIFT, "PDRSHIFT mismatch");
_Static_assert(NBPD == AMD64_NBPDR, "NBPDR mismatch");
_Static_assert(PDMASK == AMD64_PDRMASK, "PDRMASK mismatch");
_Static_assert(NPDEPG == AMD64_NPDPEPG, "NPDPEPG mismatch");
_Static_assert(PDPTSHIFT == AMD64_PDPSHIFT, "PDPSHIFT mismatch");
_Static_assert(NBPDPT == AMD64_NBPDP, "NBPDP mismatch");
_Static_assert(PDPTMASK == AMD64_PDPMASK, "PDPMASK mismatch");
_Static_assert(NPML4EPG == AMD64_NPML4EPG, "NPML4EPG mismatch");
_Static_assert(PML4SHIFT == AMD64_PML4SHIFT, "PML4SHIFT mismatch");

_Static_assert(PG_V == AMD64_PG_V, "PG_V mismatch");
_Static_assert(PG_PS == AMD64_PG_PS, "PG_PS mismatch");
_Static_assert(PG_FRAME == AMD64_PG_FRAME, "PG_FRAME mismatch");
_Static_assert(PG_PS_FRAME == AMD64_PG_PS_FRAME, "PG_PS_FRAME mismatch");
#endif

int	_amd64_native(kvm_t *);

#endif /* !__KVM_AMD64_H__ */
