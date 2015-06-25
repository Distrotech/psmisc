/*
 * lists.h	Simple doubly linked list implementation, based on
 *		<linux/list.h>, <linux/prefetch.h>, and lib/list_sort.c
 *
 * Version:	0.2 11-Dec-2012 Fink
 *
 * Copyright 2011,2012 Werner Fink, 2005,2012 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Werner Fink <werner@suse.de>, 2011
 */

#ifndef _LISTS_H
#define _LISTS_H

#include <stddef.h>
#include <sys/types.h>

typedef enum _boolean {false, true} boolean;
typedef unsigned char uchar;
#ifndef __USE_MISC
typedef unsigned short ushort;
typedef unsigned int uint;
#endif

#ifndef __OPTIMIZE__
# warning This will not compile without -O at least
#endif
#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# ifndef  inline
#  define inline		__inline__
# endif
# ifndef  restrict
#  define restrict		__restrict__
# endif
# ifndef  volatile
#  define volatile		__volatile__
# endif
# ifndef  asm
#  define asm			__asm__
# endif
# ifndef  extension
#  define extension		__extension__
# endif
#endif
#ifndef  attribute
# define attribute(attr)	__attribute__(attr)
#endif

/*
 * This is lent from the kernel by e.g. using
 *
 *   echo '#include <asm-i386/processor.h>\nint main () { prefetch(); return 0; }' | \
 *	gcc -I/usr/src/linux/include -D__KERNEL__ -x c -E -P - | \
 *	sed -rn '/void[[:blank:]]+prefetch[[:blank:]]*\(/,/^}/p'
 *
 * on the appropriate architecture (here on i686 for i586).
 */
extern inline void attribute((used,__gnu_inline__,always_inline,__artificial__)) prefetch(const void *restrict x)
{
#if   defined(__x86_64__)
    asm volatile ("prefetcht0 %0"  :: "m" (*(unsigned long *)x))
#elif defined(__ia64__)
    asm volatile ("lfetch [%0]"    :: "r" (x))
#elif defined(__powerpc64__)
    asm volatile ("dcbt 0,%0"      :: "r" (x))
#elif !defined(__CYGWIN__) && !defined(__PIC__) && defined(__i386__)
    asm volatile ("661:\n\t"
		  ".byte 0x8d,0x74,0x26,0x00\n"
		  "\n662:\n"
		  ".section .altinstructions,\"a\"\n"
		  "  .align 4\n"
		  "  .long 661b\n"
		  "  .long 663f\n"
		  "  .byte %c0\n"
		  "  .byte 662b-661b\n"
		  "  .byte 664f-663f\n"
		  ".previous\n"
		  ".section .altinstr_replacement,\"ax\"\n"
		  "   663:\n\t"
		  "   prefetchnta (%1)"
		  "   \n664:\n"
		  ".previous"
		  :: "i" ((0*32+25)), "r" (x))
#else
    __builtin_prefetch ((x), 0, 1);
#endif
    ;
}

#if defined(DEBUG) && (DEBUG > 0)
# define __align attribute((packed))
#else
# define __align attribute((aligned(sizeof(struct list_struct*))))
#endif
#define __packed attribute((packed))

#define alignof(type)		((sizeof(type)+(sizeof(void*)-1)) & ~(sizeof(void*)-1))
#define strsize(string)		((strlen(string)+1)*sizeof(char))

typedef struct list_struct {
    struct list_struct * next, * prev;
} __align list_t;

/*
 * Linked list handling
 * ====================
 * The structures which will be linked into such lists have to be of the
 * same type.  The structures may have alway a list identifier of the type
 * `list_t' as very first element.  With this the macro list_entry() can
 * be used to cast the memory address of a list member to the corresponding
 * allocated structure.
 */

/*
 * Insert new entry as next member.
 */
static inline void _insert(list_t *restrict new, list_t *restrict here) attribute((always_inline,nonnull(1,2)));
static inline void _insert(list_t *restrict new, list_t *restrict here)
{
    list_t * prev = here;
    list_t * next = here->next;

    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

#define insert(new, list)	_insert(&((new)->this), (&(list)));
#define append(new, list)	_insert(&((new)->this), (&(list))->prev);

/*
 * Set head
 */
static inline void initial(list_t *restrict head) attribute((always_inline,nonnull(1)));
static inline void initial(list_t *restrict head)
{
    head->prev = head->next = head;
}

/*
 * Remove entries, note that the pointer its self remains.
 */
static inline void delete(list_t *restrict entry) attribute((always_inline,nonnull(1)));
static inline void delete(list_t *restrict entry)
{
    list_t * prev = entry->prev;
    list_t * next = entry->next;

    next->prev = prev;
    prev->next = next;

    initial(entry);
}

/*
 * Replace an entry by a new one.
 */
static inline void replace(list_t *restrict old, list_t *restrict new) attribute((always_inline,nonnull(1,2)));
static inline void replace(list_t *restrict old, list_t *restrict new)
{
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
}

static inline void join(list_t *restrict list, list_t *restrict head) attribute((always_inline,nonnull(1,2)));
static inline void join(list_t *restrict list, list_t *restrict head)
{
    list_t * first = list->next;

    if (first != list) {
	list_t * last = list->prev;
       	list_t * at = head->next;

       	first->prev = head;
       	head->next = first;

       	last->next = at;
       	at->prev = last;
    }
}

static inline boolean list_empty(const list_t *restrict const head) attribute((always_inline,nonnull(1)));
static inline boolean list_empty(const list_t *restrict const head)
{
     return head->next == head;
}

static inline void move_head(list_t *restrict entry, list_t *restrict head) attribute((always_inline,nonnull(1,2)));
static inline void move_head(list_t *restrict entry, list_t *restrict head)
{
    list_t * prev = entry->prev;
    list_t * next = entry->next;

    next->prev = prev;		/* remove entry from old list */
    prev->next = next;

    prev = head;
    next = head->next;

    next->prev = entry;		/* and add it at head of new list */
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

static inline void move_tail(list_t *restrict entry, list_t *restrict head) attribute((always_inline,nonnull(1,2)));
static inline void move_tail(list_t *restrict entry, list_t *restrict head)
{
    list_t * prev = entry->prev;
    list_t * next = entry->next;

    next->prev = prev;		/* remove entry from old list */
    prev->next = next;

    prev = head->prev;
    next = head;

    next->prev = entry;		/* and add it at tail of new list */
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
}

/*
 * The handle of the list is named `this'
 */
#define list_entry(ptr, type)	(__extension__ ({	\
	const typeof( ((type *)0)->this ) *__mptr = (ptr);	\
	((type *)( (char *)(__mptr) - offsetof(type,this) )); }))
#define list_for_each(pos, head)	\
	for (pos = (head)->next; prefetch(pos->next), pos != (head); pos = pos->next)
#define np_list_for_each(pos, head)	\
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, safe, head)	\
	for (pos = (head)->next, safe = pos->next; pos != (head); pos = safe, safe = pos->next)
#define list_for_each_prev(pos, head)	\
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); pos = pos->prev)
#define np_list_for_each_prev(pos, head)	\
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define MAX_LIST_LENGTH_BITS 20

/*
 * Returns a list organized in an intermediate format suited
 * to chaining of merge() calls: null-terminated, no reserved or
 * sentinel head node, "prev" links not maintained.
 */
static inline list_t *merge(int (*cmp)(list_t *a, list_t *b), list_t *a, list_t *b)
{
    list_t head, *tail = &head;
    while (a && b) {
	/* if equal, take 'a' -- important for sort stability */
	if ((*cmp)(a, b) <= 0) {
	    tail->next = a;
	    a = a->next;
	} else {
	    tail->next = b;
	    b = b->next;
	}
	tail = tail->next;
    }
    tail->next = a ? a : b;
    return head.next;
}

/*
 * Combine final list merge with restoration of standard doubly-linked
 * list structure.  This approach duplicates code from merge(), but
 * runs faster than the tidier alternatives of either a separate final
 * prev-link restoration pass, or maintaining the prev links
 * throughout.
 */
static inline void merge_and_restore_back_links(int (*cmp)(list_t *a, list_t *b), list_t *head, list_t *a, list_t *b)
{
    list_t *tail = head;

    while (a && b) {
	/* if equal, take 'a' -- important for sort stability */
	if ((*cmp)(a, b) <= 0) {
	    tail->next = a;
	    a->prev = tail;
	    a = a->next;
	} else {
	    tail->next = b;
	    b->prev = tail;
	    b = b->next;
	}
	tail = tail->next;
    }
    tail->next = a ? a : b;

    do {
	/*
	 * In worst cases this loop may run many iterations.
	 * Continue callbacks to the client even though no
	 * element comparison is needed, so the client's cmp()
	 * routine can invoke cond_resched() periodically.
	 */
	(*cmp)(tail->next, tail->next);

	tail->next->prev = tail;
	tail = tail->next;
    } while (tail->next);

    tail->next = head;
    head->prev = tail;
}


/**
 * list_sort - sort a list
 * @head: the list to sort
 * @cmp: the elements comparison function
 *
 * This function implements "merge sort", which has O(nlog(n))
 * complexity.
 *
 * The comparison function @cmp must return a negative value if @a
 * should sort before @b, and a positive value if @a should sort after
 * @b. If @a and @b are equivalent, and their original relative
 * ordering is to be preserved, @cmp must return 0.
 */
static inline void list_sort(list_t *head, int (*cmp)(list_t *a, list_t *b))
{
    list_t *part[MAX_LIST_LENGTH_BITS+1]; /* sorted partial lists
						-- last slot is a sentinel */
    size_t lev;  /* index into part[] */
    size_t max_lev = 0;
    list_t *list;

    if (list_empty(head))
	return;

    memset(part, 0, sizeof(part));

    head->prev->next = NULL;
    list = head->next;

    while (list) {
	list_t *cur = list;
	list = list->next;
	cur->next = NULL;

	for (lev = 0; part[lev]; lev++) {
	    cur = merge(cmp, part[lev], cur);
	    part[lev] = NULL;
	}
	if (lev > max_lev) {
	    /* list passed to list_sort() too long for efficiency */
	    if (lev >= MAX_LIST_LENGTH_BITS)
		lev--;
	    max_lev = lev;
	}
	part[lev] = cur;
    }

    for (lev = 0; lev < max_lev; lev++) {
	if (part[lev])
	    list = merge(cmp, part[lev], list);
    }

    merge_and_restore_back_links(cmp, head, part[max_lev], list);
}

#endif /* _LISTS_H */
