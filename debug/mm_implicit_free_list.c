/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "XJTU ICS",
    /* First member's full name */
    "Hspike",
    /* First member's email address */
    "hspike@666",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

#define WORD_SIZE (sizeof(unsigned int))

#define READ(PTR) (*(unsigned int *)(PTR))
#define WRITE(PTR, VALUE) ((*(unsigned int *)(PTR)) = (VALUE))

#define PACK(SIZE, IS_ALLOC) ((SIZE) | (IS_ALLOC))

#define HEAD_PTR(PTR) ((void *)(PTR) - WORD_SIZE)

#define GET_SIZE(PTR) (unsigned int)((READ(PTR) >> 3) << 3)
#define IS_ALLOC(PTR) (READ(PTR) & (unsigned int)1)


#define TAIL_PTR(PTR) ((void *)(PTR) + GET_SIZE(HEAD_PTR(PTR)) - WORD_SIZE * 2)

#define NEXT_BLOCK(PTR) ((void *)(PTR) + GET_SIZE(HEAD_PTR(PTR)))
#define PREV_BLOCK(PTR) ((void *)(PTR) - GET_SIZE((void *)(PTR) - WORD_SIZE * 2))

#define PAGE_SIZE (1 << 12)

void *HeapList = NULL;

#define BLOCK_SIZE(PTR) (unsigned int)(GET_SIZE(HEAD_PTR(PTR)))
#define IS_BLOCK_ALLOC(PTR) (IS_ALLOC(HEAD_PTR(PTR)))

void *Merge(void *Ptr) {
    void * nxt_b=NEXT_BLOCK(Ptr);
    void * pre_b=PREV_BLOCK(Ptr);

    unsigned size=BLOCK_SIZE(Ptr);
    if(!IS_BLOCK_ALLOC(nxt_b))
        size+=BLOCK_SIZE(nxt_b);
    if(!IS_BLOCK_ALLOC(pre_b))
    {
        size+=BLOCK_SIZE(pre_b);
        Ptr=pre_b;
    }
    WRITE(HEAD_PTR(Ptr),PACK(size,0));
    WRITE(TAIL_PTR(Ptr),PACK(size,0));
    // printf("Merge Block: %p, Size = %d\n",Ptr,size);
    return Ptr;
}

void Place(void *Ptr, unsigned Size) {
    unsigned size=BLOCK_SIZE(Ptr);
    if(size-Size<=sizeof(size_t))
    {
        WRITE(HEAD_PTR(Ptr),PACK(size,1));
        WRITE(TAIL_PTR(Ptr),PACK(size,1));
    }
    else 
    {
        WRITE(HEAD_PTR(Ptr),PACK(Size,1));
        WRITE(TAIL_PTR(Ptr),PACK(Size,1));
        // printf("Place Block: %p, Size = %u\n",Ptr,Size);
        Ptr=NEXT_BLOCK(Ptr);
        size=size-Size;
        // printf("Remain Block: %p, Size = %u\n",Ptr,size);
        WRITE(HEAD_PTR(Ptr),PACK(size,0));
        WRITE(TAIL_PTR(Ptr),PACK(size,0));
    }
    return;
}

void *FirstFit(size_t Size) {
    void * ptr=HeapList;
    while(BLOCK_SIZE(ptr))
    {
        if((!IS_BLOCK_ALLOC(ptr)) && BLOCK_SIZE(ptr)>=Size) return ptr;
        else ptr=NEXT_BLOCK(ptr); 
    }
    return NULL;
}

int mm_init() {
    HeapList = mem_sbrk(WORD_SIZE << 2);
    if (HeapList == (void *)-1) return -1;
    WRITE(HeapList, 0);
    // Prologue block
    WRITE(HeapList + WORD_SIZE * 1, PACK(8, 1));
    WRITE(HeapList + WORD_SIZE * 2, PACK(8, 1));
    WRITE(HeapList + WORD_SIZE * 3, PACK(0, 1));
    HeapList+=WORD_SIZE * 2;
    // printf("\nHeapList = %p\n",HeapList);
    return 0;
}

void *mm_malloc(size_t size) {
    // printf("\n");
    if (size == 0) return NULL;
    size += (WORD_SIZE << 1);
    if ((size & (unsigned int)7) > 0) size += (1 << 3) - (size & 7);
    void *Ptr = FirstFit(size);
    if (Ptr != NULL) {
        Place(Ptr, size);
        // printf("Block Malloc: %p, Size = %u\n",Ptr,size);
        return Ptr;
    }
    unsigned int SbrkSize = MAX(size, PAGE_SIZE);
    void *NewPtr = mem_sbrk(SbrkSize);
    if (NewPtr == (void *)-1) return NULL;
    WRITE(NewPtr - WORD_SIZE, PACK(SbrkSize, 0));
    WRITE(mem_heap_hi() - 3 - WORD_SIZE, PACK(SbrkSize, 0));
    WRITE(mem_heap_hi() - 3, PACK(0, 1));
    NewPtr = Merge(NewPtr);
    Place(NewPtr, size);
    // printf("New Malloc: %p, Size = %u\n",NewPtr,size);
    return NewPtr;
}

void mm_free(void *ptr) {
    void *Header = HEAD_PTR(ptr), *Tail = TAIL_PTR(ptr);
    // printf("Free: %p\n",ptr);
    unsigned int Size = GET_SIZE(Header);
    WRITE(Header, PACK(Size, 0));
    WRITE(Tail, PACK(Size, 0));
    Merge(ptr);
}

void *mm_realloc(void *ptr, size_t size) {
    unsigned int BlkSize = GET_SIZE(HEAD_PTR(ptr));
    if ((size & (unsigned int)7) > 0) size += (1 << 3) - (size & 7);
    if (BlkSize >= size + WORD_SIZE * 2) return ptr;
    void *NewPtr = mm_malloc(size);
    if (NewPtr == NULL) return NULL;
    memmove(NewPtr, ptr, size);
    mm_free(ptr);
    return NewPtr;
}

/*
static void mm_printblock(void * ptr) {
    printf("address = %p\n",ptr);
    printf("size = %d\n",BLOCK_SIZE(ptr));
    // printf("%d\n")
}
*/
