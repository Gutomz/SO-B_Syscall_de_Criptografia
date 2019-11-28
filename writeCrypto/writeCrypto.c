#include <linux/kernel.h>
#include <linux/string.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <linux/mm.h>
#include <linux/syscalls.h>

#define CRYPT_BLOCK_SIZE 16

void hexdump_write(unsigned char *buff, unsigned int len)
{
	 unsigned char *aux = buff;
	 printk(KERN_INFO "modcrypto: HEXDUMP:\n");
	 while(len--) { printk(KERN_CONT "%02x[%c] ", *aux, *aux); aux++; }
	 printk("\n");
}

static int encrypt(char *buff, int len_buff)
{
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_scratchpad;
	char *scratchpad = NULL;
	struct scatterlist sg_encrypted;
	char *encrypted_buff = NULL;
	char *encrypteddata = NULL;
	char *key = NULL;
	int ret = -EFAULT;
	int i;

	pr_info("modcrypto: Initialized Encryption\n");

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
	encrypted_buff = kmalloc(len_buff, GFP_KERNEL);
	if (!scratchpad || !encrypted_buff) {
		pr_info("modcrypto: Could not allocate scratchpad or encrypted_buff\n");
		goto out;
	}

	for(i = 0; i < len_buff; i++) scratchpad[i] = buff[i];

	sg_init_one(&sg_scratchpad, scratchpad, len_buff);
	sg_init_one(&sg_encrypted, encrypted_buff, len_buff);

	skcipher_request_set_crypt(req, &sg_scratchpad, &sg_encrypted, len_buff, NULL);

	ret = crypto_skcipher_encrypt(req);

	if(ret){
		pr_info("modcrypto: Failed to encrypt\n");
		goto out;
	}

	encrypteddata = sg_virt(&sg_encrypted);

	pr_info("modcrypto: ------| CRYPT RESULT |------\n");
	hexdump_write(encrypteddata, len_buff);
	pr_info("modcrypto: ------| CRYPT RESULT |------\n");

	for(i = 0; i < len_buff;i++){
	 	buff[i] = encrypteddata[i];
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
	if (encrypted_buff)
		kfree(encrypted_buff);

	return ret;
}

asmlinkage ssize_t sys_writeCrypto(int _fd, const void *_buf, size_t _len){
	int i, n_blocks, crypt_len;	
	char *buf;
	mm_segment_t oldfs;
	ssize_t ret;
	int len = _len;
	int fd = _fd;

	if(len % CRYPT_BLOCK_SIZE) n_blocks = 1 + (len / CRYPT_BLOCK_SIZE);
	else n_blocks = len / CRYPT_BLOCK_SIZE; 

	crypt_len = n_blocks * CRYPT_BLOCK_SIZE;

	buf = kmalloc(crypt_len, GFP_KERNEL);

	for(i = 0; i < crypt_len; i++){
		if(i < len) sprintf(&buf[i], "%c", ((char *)_buf)[i]);
		else buf[i] = 0;
	}

	if(encrypt(buf, crypt_len)){
		kfree(buf);
		return 0;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = sys_write(fd, buf, crypt_len);

	set_fs(oldfs);

	kfree(buf);

	return ret;
}
