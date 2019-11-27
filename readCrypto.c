#include <linux/kernel.h>
#include <linux/string.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/mm.h>
#include <linux/syscalls.h>

#define CRYPT_BLOCK_SIZE 16

void hexdump(unsigned char *buff, unsigned int len)
{
	 unsigned char *aux = buff;
	 printk(KERN_INFO "modcrypto: HEXDUMP:\n");
	 while(len--) { printk(KERN_CONT "%02x[%c] ", *aux, *aux); aux++; }
	 printk("\n");
}

static int modcrypto_decrypt(char *buff, int len_buff)
{
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_scratchpad;
	char *scratchpad = NULL;
	struct scatterlist sg_decrypted;
	char *decrypted_buff = NULL;
	char *decrypteddata = NULL;
	char *key = NULL;
	int ret = -EFAULT;
	int i;

	pr_info("modcrypto: Initialized Decription");

	key = kmalloc(CRYPT_BLOCK_SIZE, GFP_KERNEL);
	for(i = 0; i < CRYPT_BLOCK_SIZE; i++) key[i] = 'X';

	skcipher = crypto_alloc_skcipher("ecb(aes)", 0, 0);
    if (IS_ERR(skcipher)) {
		pr_info("modcrypto: Could not allocate skcipher handle\n");
    	return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("modcrypto: Could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	if (crypto_skcipher_setkey(skcipher, key, CRYPT_BLOCK_SIZE)) {
		pr_info("modcrypto: Key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	scratchpad = kmalloc(len_buff, GFP_KERNEL);
	decrypted_buff = kmalloc(len_buff, GFP_KERNEL);
	if (!scratchpad || !decrypted_buff) {
		pr_info("modcrypto: Could not allocate scratchpad or decrypted_buff\n");
		goto out;
	}

	for(i = 0; i < len_buff;i++) scratchpad[i] = buff[i];

	sg_init_one(&sg_scratchpad, scratchpad, len_buff);
	sg_init_one(&sg_decrypted, decrypted_buff, len_buff);

	skcipher_request_set_crypt(req, &sg_scratchpad, &sg_decrypted, len_buff, NULL);

	ret = crypto_skcipher_decrypt(req);

	if(ret){
		pr_info("modcrypto: Failed to decrypt\n");
		goto out;
	}

	decrypteddata = sg_virt(&sg_decrypted);

	pr_info("modcrypto: ------| DECRYPT RESULT |------\n");
	hexdump(decrypteddata, len_buff);
	pr_info("modcrypto: ------| DECRYPT RESULT |------\n");

	for(i = 0; i < len_buff;i++){
	 	buff[i] = decrypteddata[i];
	}

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if(key)
		kfree(key);
	if (scratchpad)
		kfree(scratchpad);
	if (decrypted_buff)
		kfree(decrypted_buff);

	return ret;
}

asmlinkage ssize_t readCrypto(int _fd, const void *_buf, size_t _len){
	int i, n_blocks, crypt_len;	
	char* buf;
    mm_segment_t oldfs;
	int len = _len;
	int fd = _fd;

	if(len % CRYPT_BLOCK_SIZE) n_blocks = 1 + (len / CRYPT_BLOCK_SIZE);
	else n_blocks = len / CRYPT_BLOCK_SIZE; 

	crypt_len = n_blocks * CRYPT_BLOCK_SIZE;

	buf = kmalloc(crypt_len, GFP_KERNEL);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	sys_read(fd, buf, crypt_len);

	if(modcrypto_decrypt(buf, crypt_len)){
		kfree(buf);
		return -1;
	}

    for(i = 0; i < len; i++){
        ((char *)_buf)[i] = buf[i];
    }

    set_fs(oldfs);

    kfree(buf);

	return len;
}
