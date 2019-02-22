#include <stdlib.h>
#include <pthread.h>
#include "kvm/disk-image.h"
#include "block-swap.h"
#include "ioh.h"
#include "aio.h"

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
    u64 total;
    const struct iovec *iov;
    int iovcount;
    void *param;
    int type;
    u8 *buffer;
};

static ioh_event perform_io_event;

static void io_done(void *opaque, int ret)
{
    struct io_info *info = opaque;

    if (info->type == 0) {
        int offset = 0;
        const struct iovec *iov = info->iov;
        for (int i = 0; i < info->iovcount; ++i, ++iov) {
            memcpy(iov->iov_base, info->buffer + offset, iov->iov_len);
            offset += iov->iov_len;
        }
    }

    struct disk_image *disk = info->disk;
    disk->disk_req_cb(info->param, info->total);
    free(info->buffer);
    free(info);
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(infos_list);

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
    info->total = total;
    info->iov = iov;
    info->iovcount = iovcount;
    info->param = param;
    info->type = type;

    pthread_mutex_lock(&mutex);
    list_add_tail(&info->list, &infos_list);
    pthread_mutex_unlock(&mutex);

    ioh_event_set(&perform_io_event);

    return 1;
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

static void disk_swap_perform_ios(void *bs) {
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

        info->buffer = malloc(info->total);
        if (info->type == 0) {
            swap_aio_read(bs, info->sector, info->buffer,
                    info->total >> SECTOR_SHIFT,
                    io_done, info);
        } else {
            const struct iovec *iov = info->iov;
            int offset = 0;
            for (int i = 0; i < info->iovcount; ++i, ++iov) {
                memcpy(info->buffer + offset, iov->iov_base, iov->iov_len);
                offset += iov->iov_len;
            }
            swap_aio_write(bs, info->sector,
                    info->buffer, info->total >> SECTOR_SHIFT,
                    io_done, info);
        }
    }
}

static void *disk_swap_thread(void *bs)
{
    aio_global_init();

    for (;;) {
        aio_wait();
    }
    return NULL;
}

struct disk_image *swap_image__probe(int fd, struct stat *st, bool readonly)
{
	struct disk_image *disk;
    struct BlockDriverState *bs = calloc(1, sizeof(*bs));
    swap_open(bs, "arch.swap", 0);

    disk = disk_image__new(fd, 0x1000ULL << 32ULL, &swap_image_ops, DISK_IMAGE_REGULAR);

#ifdef CONFIG_HAS_AIO
    if (!IS_ERR_OR_NULL(disk))
        disk->async = 1;
#endif

    ioh_event_init(&perform_io_event, disk_swap_perform_ios, bs);

    pthread_t tid;
    pthread_create(&tid, NULL, disk_swap_thread, bs);

    return disk;
}
