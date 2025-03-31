#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "cryptomod.h"

#define MAX_DATA_SIZE 2048

DEFINE_MUTEX(lock);

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

// For ADV mode data
// u8 *data_16;
// size_t data_len;

// Frequency matrix
int *freq_buf;

size_t total_read;
size_t total_write;

struct cryptodev_ctx {
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    // key
    u8 key[CM_KEY_MAX_LEN];
    size_t key_len;
    enum IOMode io_mode;
    enum CryptoMode c_mode;
    bool finalized;

    // data
    u8 *data;
    size_t data_len;
    size_t read;
    size_t write;
    size_t enc;
};

static int crypto_dev_open(struct inode *inode, struct file *file) {
    struct cryptodev_ctx *ctx;

    ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;

    ctx->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(ctx->tfm)) {
        pr_err("Error allocating ecb(aes) handle: %ld\n", PTR_ERR(ctx->tfm));
    }

    ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);

    ctx->data = kmalloc(MAX_DATA_SIZE, GFP_KERNEL);
    ctx->data_len = MAX_DATA_SIZE;

    // memset(freq_buf, 0, sizeof(freq_buf));
    ctx->read = 0;
    ctx->write = 0;
    ctx->enc = 0;

    file->private_data = ctx;

    return 0;
}

static int crypto_dev_close(struct inode *inode, struct file *file) {

    // struct cryptodev_ctx *ctx = file->private_data;
    
    // printk(KERN_INFO "cryptodev: device closed.\n");

    // ctx->finalized = 0;

    return 0;
}

static ssize_t crypto_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {

    struct cryptodev_ctx *ctx = f->private_data;
    size_t to_read, available;
    int err = 0;

    // printk(KERN_INFO "cryptodev: read %zu bytes @ %llu.\n", len, *off);

    // The device is not properly set up
    if (!ctx || !ctx->tfm || ctx->key_len == 0) {
        return -EINVAL;
    }

    // mutex_lock(&ctx->lock);

    if (ctx->io_mode == BASIC) {

        available = ctx->write - ctx->read;

        if (available <= 0) {
            if (ctx->finalized)
                err = 0; // If no data is available and CM_IOC_FINALIZE has been called, return 0
            else
                err = -EAGAIN; // If no data is available and CM_IOC_FINALIZE has not been called, return -EAGAIN
        }

        to_read = min(len, available);
        if (copy_to_user(buf, ctx->data + ctx->read, to_read)) {
            err = -EBUSY;
        }

        ctx->read += to_read;
        err = to_read;

    } else if (ctx->io_mode == ADV) {

        if (ctx->c_mode == ENC) {

            struct scatterlist sg;
            DECLARE_CRYPTO_WAIT(wait);

            available = ctx->write - ctx->read;

            if (available <= 0) {
                if (ctx->finalized)
                    err = 0; // If no data is available and CM_IOC_FINALIZE has been called, return 0
                else
                    err = -EAGAIN; // If no data is available and CM_IOC_FINALIZE has not been called, return -EAGAIN
            }

            to_read = min(len, available);

            size_t enc_len = (ctx->write - ctx->enc) - ((ctx->write - ctx->enc) % 16);

            if (enc_len > 0 && ctx->finalized == 0) {
                sg_init_one(&sg, ctx->data + ctx->enc, enc_len);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, enc_len, NULL);
                err = crypto_wait_req(crypto_skcipher_encrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error encrypting data: %d\n", err);
                }

                pr_debug("Encryption was successful\n");

                mutex_lock(&lock);
                for (size_t i = ctx->enc; i < enc_len; i++) {
                    freq_buf[ctx->data[i]]++;
                }
                mutex_unlock(&lock);
            }

            if (copy_to_user(buf, ctx->data + ctx->read, to_read)) {
                err = -EBUSY;
            }

            ctx->enc = ctx->enc + enc_len;
            ctx->read += to_read;

            err = to_read;
        } else if (ctx->c_mode == DEC) {

            struct scatterlist sg;
            DECLARE_CRYPTO_WAIT(wait);

            available = ctx->write - ctx->read;

            if (available < 16) {
                if (ctx->finalized)
                    err = 0; // If no data is available and CM_IOC_FINALIZE has been called, return 0
                else
                    err = -EAGAIN; // If no data is available and CM_IOC_FINALIZE has not been called, return -EAGAIN
            }

            to_read = min(len, available - 16);

            size_t enc_len = (ctx->write - ctx->enc) - ((ctx->write - ctx->enc) % 16) -16;

            if (enc_len > 16 && ctx->finalized == 0) {

                sg_init_one(&sg, ctx->data + ctx->enc, enc_len);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, enc_len, NULL);
                err = crypto_wait_req(crypto_skcipher_decrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error decrypting data: %d\n", err);
                }

                pr_debug("Decryption was successful\n");

            }

            if (copy_to_user(buf, ctx->data + ctx->read, to_read)) {
                err = -EBUSY;
            }

            ctx->enc = ctx->enc + enc_len;
            ctx->read += to_read;
            err = to_read;
        }

    }

    mutex_lock(&lock);
    total_read += to_read;
    mutex_unlock(&lock);
    return err;

}

static ssize_t crypto_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {

    struct cryptodev_ctx *ctx = f->private_data;
    int err = 0;
    u8 *kbuf;

    // printk(KERN_INFO "cryptodev: write %zu bytes @ %llu.\n", len, *off);

    if (!ctx || !ctx->tfm || ctx->key_len == 0) {
        return -EINVAL;
    }

    if (ctx->finalized) {
        return -EINVAL;
    }

    // mutex_lock(&ctx->lock);

    kbuf = kmalloc(len+10, GFP_KERNEL);

    // Copying data between user space and kernel space has failed
    err = copy_from_user(kbuf, buf, len);

    if (ctx->io_mode == BASIC) {
        // Store data in buffer, process only at FINALIZE
        if (ctx->write + len > MAX_DATA_SIZE) {
            err = -EAGAIN;
            // mutex_unlock(&ctx->lock);
        }

        memcpy(ctx->data + ctx->write, kbuf, len);
        ctx->write += len;
        err = len;

    } else if (ctx->io_mode == ADV) {

        // if (ctx->c_mode == ENC) {

            u8 *tmp = ctx->data;
            int move = ctx->write - ctx->read;

            if (ctx->write + len >= ctx->data_len) {

                int new_size = 2 * (ctx->write + len);
                u8 *new_data = vzalloc(new_size);
                
                memcpy(new_data, tmp + ctx->read, move);
                ctx->data = new_data;
                ctx->data_len = new_size;

                // kfree(tmp);
                // printk("%d\n", new_size);

            }

            ctx->write -= ctx->read;
            ctx->enc -= ctx->read;
            ctx->read = 0;

            memcpy(ctx->data + ctx->write, kbuf, len);
            ctx->write += len;
            err = len;

        // }
    }

    kfree(kbuf);
    mutex_lock(&lock);
    total_write += len;
    mutex_unlock(&lock);
    return err;
}

static long crypto_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct cryptodev_ctx *ctx = file->private_data;
    struct CryptoSetup setup;

    // const size_t datasize = 512;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);

    int err = 0;

    switch(cmd) {
    
    case CM_IOC_SETUP:

        if (copy_from_user(&setup, (void __user *)arg, sizeof(setup))) {
            return -EINVAL;
        }

        if (setup.c_mode != ENC && setup.c_mode != DEC) {
            return -EINVAL;
        }

        if (setup.io_mode != BASIC && setup.io_mode != ADV) {
            return -EINVAL;
        }

        memcpy(ctx->key, setup.key, sizeof(setup.key));
        ctx->key_len = setup.key_len;
        ctx->io_mode = setup.io_mode;
        ctx->c_mode = setup.c_mode;
        ctx->finalized = 0;

        ctx->read = 0;
        ctx->write = 0;
        ctx->enc = 0;

        if (!(ctx->key_len == 16 || ctx->key_len == 24 || ctx->key_len == 32)) {
            return -EINVAL;
        }

        err = crypto_skcipher_setkey(ctx->tfm, ctx->key, ctx->key_len);
        if (err) {
            return -EINVAL;
        }

        return 0;

    case CM_IOC_FINALIZE:

        if (!ctx || !ctx->tfm || ctx->key_len == 0) {
            return -EINVAL;
        }

        // mutex_lock(&ctx->lock);

        ctx->finalized = 1;

        if (ctx->io_mode == BASIC) {
            if (ctx->c_mode == ENC) {

                // Padding for encryption
                size_t padding_len = 16 - (ctx->write % 16);
                
                if (padding_len == 0) {
                    padding_len = 16;
                }

                // Append padding bytes
                memset(ctx->data + ctx->write, padding_len, padding_len);

                ctx->write += padding_len;
                ctx->enc += padding_len;

                // Encrypt data
                sg_init_one(&sg, ctx->data, ctx->write);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, ctx->write, NULL);
                err = crypto_wait_req(crypto_skcipher_encrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error encrypting data: %d\n", err);
                        goto out;
                }

                pr_debug("Encryption was successful\n");

                mutex_lock(&lock);
                for (size_t i = 0; i < ctx->write; i++) {
                    freq_buf[ctx->data[i]]++;
                }
                mutex_unlock(&lock);

            } else if (ctx->c_mode == DEC) {

                sg_init_one(&sg, ctx->data, ctx->write);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, ctx->write, NULL);
                err = crypto_wait_req(crypto_skcipher_decrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error decrypting data: %d\n", err);
                        goto out;
                }

                pr_debug("Decryption was successful\n");

                size_t pad_len = ctx->data[ctx->write - 1];
                if (pad_len > 16) {
                    return -EINVAL;
                }
                ctx->write -= pad_len;
            }

out:
            crypto_free_skcipher(ctx->tfm);
            skcipher_request_free(ctx->req);
            // mutex_unlock(&ctx->lock);
            return err;

        } else if (ctx->io_mode == ADV) {
            if (ctx->c_mode == ENC) {

                size_t padding_len = 16 - ((ctx->write - ctx->enc) % 16);

                memset(ctx->data + ctx->write, padding_len, padding_len);

                ctx->write += padding_len;

                // Encrypt data
                sg_init_one(&sg, ctx->data + ctx->enc, ctx->write - ctx->enc);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, ctx->write - ctx->enc, NULL);
                err = crypto_wait_req(crypto_skcipher_encrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error encrypting data: %d\n", err);
                }

                pr_debug("Encryption was successful\n");

                mutex_lock(&lock);
                for (size_t i = ctx->enc; i < ctx->write; i++) {
                    freq_buf[ctx->data[i]]++;
                }
                mutex_unlock(&lock);

            } else if (ctx->c_mode == DEC) {
                // size_t enc_len = (write - enc) - ((write - enc) % 16);
                size_t pad_len = 0;

                // Decrypt data
                sg_init_one(&sg, ctx->data + ctx->enc, ctx->write - ctx->enc);
                skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                                CRYPTO_TFM_REQ_MAY_SLEEP,
                                            crypto_req_done, &wait);
                skcipher_request_set_crypt(ctx->req, &sg, &sg, ctx->write - ctx->enc, NULL);
                err = crypto_wait_req(crypto_skcipher_decrypt(ctx->req), &wait);
                if (err) {
                        pr_err("Error decrypting data: %d\n", err);
                }

                pr_debug("Decryption was successful\n");

                // size_t pad_len = write - enc;
                if (pad_len > 16) {
                    return -EINVAL;
                }
                ctx->write -= pad_len;
                ctx->enc = ctx->write;
            }
        }
        // mutex_unlock(&ctx->lock);

        return err;
    
    case CM_IOC_CLEANUP:
        
        if (!ctx || !ctx->tfm)
            return -EINVAL;

        ctx->finalized = 0;

        memset(ctx->data, 0, MAX_DATA_SIZE);
        // memset(freq_buf, 0, sizeof(int)*260);
        total_read = 0;
        total_write = 0;
        return 0;

    case CM_IOC_CNT_RST:

        memset(ctx->data, 0, MAX_DATA_SIZE);
        mutex_lock(&lock);
        memset(freq_buf, 0, sizeof(int)*260);
        total_read = 0;
        total_write = 0;
        mutex_unlock(&lock);
        return 0;

    }
    return err;
}

static const struct file_operations crypto_dev_fops = {
	.owner = THIS_MODULE,
	.open = crypto_dev_open,
	.read = crypto_dev_read,
	.write = crypto_dev_write,
	.unlocked_ioctl = crypto_dev_ioctl,
	.release = crypto_dev_close
};

static int crypto_proc_read(struct seq_file *m, void *v) {

    seq_printf(m, "%ld %ld \n", total_read, total_write);

    for (int i = 0; i < 256; i++) {
        if (i % 16 == 0 && i != 0) {
            seq_putc(m, '\n'); // New line after each row
        }
        seq_printf(m, "%d ", freq_buf[i]);
    }
    seq_putc(m, '\n');

    return 0;
}

static int crypto_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, crypto_proc_read, NULL);
}

static const struct proc_ops crypto_proc_fops = {
	.proc_open = crypto_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *crypto_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init crypto_init(void) {
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = crypto_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
		goto release_class;
	cdev_init(&c_dev, &crypto_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

    proc_create("cryptomod", 0, NULL, &crypto_proc_fops);

    freq_buf = kmalloc(sizeof(int)*260, GFP_KERNEL);

    memset(freq_buf, 0, sizeof(int)*260);
    total_read = 0;
    total_write = 0;
	// printk(KERN_INFO "cryptodev: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit crypto_cleanup(void) {

    remove_proc_entry("cryptomod", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	// printk(KERN_INFO "crypto: cleaned up.\n");
}

module_init(crypto_init);
module_exit(crypto_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yung-Hsuan Tsao");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
