#include <stdlib.h>
#include <pthread.h>
#include "kvm/disk-image.h"
#include "block-swap.h"

#include <linux/err.h>

#include <assert.h>

ssize_t swap_image__io(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param, int type);

ssize_t swap_image__read(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param);

ssize_t swap_image__write(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param);

struct io_info {
    struct disk_image *disk;
    int type;
    int count;
    u64 total;
	void *disk_req_cb_param;
	void (*disk_req_cb)(void *param, long len);
};

static void io_done(void *opaque, int ret)
{
    struct io_info *ri = opaque;
    if (--(ri->count) == 0) {
        if (ri->disk_req_cb) {
            //u64 dummy = 1;
            //write(ri->disk->evt, &dummy, sizeof(dummy));
            //ri->disk_req_cb(ri->disk_req_cb_param, ri->total);

            struct iocb iocb;
            struct disk_image *disk = ri->disk;
            /* fake read to trigger io callback. */
            char dummy;
            struct iovec iov = {&dummy, sizeof(dummy)};
            aio_preadv(disk->ctx, &iocb, disk->fd, &iov, 1, 0,
                    disk->evt, ri->disk_req_cb_param);
        }
        free(ri);
    }
}

#define MAX_IOS 512
struct swap_io_info {
    struct io_info *info;
    int type;
    void *dst;
    u64 sector;
    u64 n;
};
static struct swap_io_info *infos[MAX_IOS];
static volatile int prod, cons;

extern void ioh_wakeup(void);

ssize_t swap_image__io(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param, int type)
{
    struct io_info *info = malloc(sizeof(struct io_info));
    u64 total = 0;
    int i;
    for (i = 0; i < iovcount; ++i) {
		total += iov[i].iov_len;
    }
    info->disk = disk;
    info->type = type;
    info->count = iovcount;
    info->disk_req_cb = disk->disk_req_cb;
    info->disk_req_cb_param = param;
    info->total = total;

    //printf("%s %llx %llx type=%d\n", __FUNCTION__, sector, total >> SECTOR_SHIFT, type);

    for (int i = 0; i < iovcount; ++i) {
        u64 n = iov[i].iov_len >> SECTOR_SHIFT;
        struct swap_io_info *swio = calloc(1, sizeof(struct swap_io_info));
        swio->type = type;
        swio->dst = iov[i].iov_base;
        swio->sector = sector;
        swio->n = n;
        swio->info = info;
        infos[__sync_fetch_and_add(&prod, 1) & (MAX_IOS - 1)] = swio;
		sector += n;
	}
    ioh_wakeup();

    return total;
}

ssize_t swap_image__read(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param)
{
    return swap_image__io(disk, sector, iov, iovcount, param, 0);
}

ssize_t swap_image__write(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param)
{
    return swap_image__io(disk, sector, iov, iovcount, param, 1);
}

static struct disk_image_operations swap_image_ops = {
	.read	= swap_image__read,
	.write	= swap_image__write,
};

extern void swap_aio_wait(void);
extern void swap_aio_init(void);

static void *disk_swap_thread(void *bs)
{
    swap_aio_init();

    for (;;) {
        for (;;) {
            int start = __sync_fetch_and_add(&cons, 0) & (MAX_IOS - 1);
            int end = __sync_fetch_and_add(&prod, 0) & (MAX_IOS - 1);

            if (start == end) {
                break;
            }
            struct swap_io_info *swio = infos[start];

            if (swio->type == 0) {
                swap_aio_read(bs, swio->sector, swio->dst, swio->n, io_done, swio->info);
            } else {
                swap_aio_write(bs, swio->sector, swio->dst, swio->n, io_done, swio->info);
            }
            free(swio);
            infos[start] = NULL;
            __sync_fetch_and_add(&cons, 1);
        }
        swap_aio_wait();
    }
    return NULL;
}

struct disk_image *swap_image__probe(int fd, struct stat *st, bool readonly)
{
	struct disk_image *disk;
    struct BlockDriverState *bs = calloc(1, sizeof(*bs));
    swap_open(bs, "arch.swap", 0);

    disk = disk_image__new(fd, st->st_size, &swap_image_ops, DISK_IMAGE_REGULAR);
#ifdef CONFIG_HAS_AIO
    if (!IS_ERR_OR_NULL(disk))
        disk->async = 1;
#endif

    pthread_t tid;
    pthread_create(&tid, NULL, disk_swap_thread, bs);

    return disk;
}
