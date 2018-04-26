#include <stdlib.h>
#include <pthread.h>
#include "kvm/disk-image.h"
#include "block-swap.h"

#include <linux/err.h>
#include <linux/list.h>

#include <assert.h>

ssize_t swap_image__io(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param, int type);

ssize_t swap_image__read(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param);

ssize_t swap_image__write(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param);

struct io_info {
    struct list_head list;
    struct disk_image *disk;
    u64 sector;
    const struct iovec *iov;
    int iovcount;
    void *param;
    int type;
};

static void io_done(void *opaque, int ret)
{
    struct io_info *info = opaque;
    if (--(info->iovcount) == 0) {
        struct iocb iocb;
        struct disk_image *disk = info->disk;
        /* fake read to trigger io callback. */
        char dummy;
        struct iovec iov = {&dummy, sizeof(dummy)};
        aio_preadv(disk->ctx, &iocb, disk->fd, &iov, 1, 0,
                disk->evt, info->param);
        free(info);
    }
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(infos_list);

extern void ioh_wakeup(void);

ssize_t swap_image__io(struct disk_image *disk, u64 sector, const struct iovec *iov,
				int iovcount, void *param, int type)
{
    struct io_info *info = calloc(1, sizeof(struct io_info));
    u64 total = 0;
    for (int i = 0; i < iovcount; ++i) {
		total += iov[i].iov_len;
    }
    info->disk = disk;
    info->sector = sector;
    info->iov = iov;
    info->iovcount = iovcount;
    info->param = param;
    info->type = type;

    pthread_mutex_lock(&mutex);
    list_add_tail(&info->list, &infos_list);
    pthread_mutex_unlock(&mutex);

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
            struct io_info *info = NULL;
            pthread_mutex_lock(&mutex);
            if (!list_empty(&infos_list)) {
                info = list_first_entry(&infos_list, struct io_info, list);
                list_del(&info->list);
            }
            pthread_mutex_unlock(&mutex);

            if (!info) {
                break;
            }

            const struct iovec *iov = info->iov;
            /* Contents of "info" are likely to change under us due to callbacks */
            u64 sector = info->sector;
            int count = info->iovcount;
            int type = info->type;
            for (int i = 0; i < count; ++i, ++iov) {
                u64 n = iov->iov_len >> SECTOR_SHIFT;
                if (type == 0) {
                    swap_aio_read(bs, sector, iov->iov_base, n, io_done, info);
                } else {
                    swap_aio_write(bs, sector, iov->iov_base, n, io_done, info);
                }
                sector += n;
            }
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
