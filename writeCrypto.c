#include <linux/kernel.h>
#include <linux/string.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#define CRYPT_BLOCK_SIZE 16
#define KEY "ABCDEF0123456789"

static int modcrypto_encrypt(char *buff, int len_buff)
{
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_scratchpad;
	char *scratchpad = NULL;
	struct scatterlist sg_encrypted;
	char *encrypted_buff = NULL;
	char *encrypteddata = NULL;
	int ret = -EFAULT;

	int num_blocks;
	int len_scratchpad;
	int i;

	pr_info("modcrypto: Initialized Encryption\n");

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

	if (crypto_skcipher_setkey(skcipher, KEY, CRYPT_BLOCK_SIZE)) {
		pr_info("modcrypto: Key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	if(len_buff % CRYPT_BLOCK_SIZE)num_blocks = 1 + (len_buff / CRYPT_BLOCK_SIZE);
	else num_blocks = len_buff / CRYPT_BLOCK_SIZE;

	len_scratchpad = num_blocks * CRYPT_BLOCK_SIZE;


	scratchpad = kmalloc(len_scratchpad, GFP_KERNEL);
	encrypted_buff = kmalloc(len_scratchpad, GFP_KERNEL);
	if (!scratchpad || !encrypted_buff) {
		pr_info("modcrypto: Could not allocate scratchpad or encrypted_buff\n");
		goto out;
	}

	for(i = 0; i < len_scratchpad;i++){
		if(i < len_buff) scratchpad[i] = buff[i];
		else scratchpad[i] = 0;
	}

	sg_init_one(&sg_scratchpad, scratchpad, len_scratchpad);
	sg_init_one(&sg_encrypted, encrypted_buff, len_scratchpad);

	skcipher_request_set_crypt(req, &sg_scratchpad, &sg_encrypted, len_scratchpad, NULL);

	ret = crypto_skcipher_encrypt(req);

	if(ret){
		pr_info("modcrypto: Failed to encrypt\n");
		goto out;
	}

	encrypteddata = sg_virt(&sg_encrypted);

	for(i = 0; i < len_scratchpad;i++){
		buff[i] = encrypteddata[i];
	}

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (encrypted_buff)
		kfree(encrypted_buff);

	return ret;
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
	int ret = -EFAULT;

	int num_blocks;
	int len_scratchpad;
	int i;

	pr_info("modcrypto: Initialized Decription");

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

	if (crypto_skcipher_setkey(skcipher, KEY, CRYPT_BLOCK_SIZE)) {
		pr_info("modcrypto: Key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}
	 
	if(len_buff % CRYPT_BLOCK_SIZE)num_blocks = 1 + (len_buff / CRYPT_BLOCK_SIZE);
	else num_blocks = len_buff / CRYPT_BLOCK_SIZE;

	len_scratchpad = num_blocks * CRYPT_BLOCK_SIZE;

	scratchpad = kmalloc(len_scratchpad, GFP_KERNEL);
	decrypted_buff = kmalloc(len_scratchpad, GFP_KERNEL);
	if (!scratchpad || !decrypted_buff) {
		pr_info("modcrypto: Could not allocate scratchpad or decrypted_buff\n");
		goto out;
	}

	for(i = 0; i < len_scratchpad;i++){
		if(i < len_buff) scratchpad[i] = buff[i];
		else scratchpad[i] = 0;
	}

	sg_init_one(&sg_scratchpad, scratchpad, len_scratchpad);
	sg_init_one(&sg_decrypted, decrypted_buff, len_scratchpad);

	skcipher_request_set_crypt(req, &sg_scratchpad, &sg_decrypted, len_scratchpad, NULL);

	ret = crypto_skcipher_decrypt(req);

	if(ret){
		pr_info("modcrypto: Failed to decrypt\n");
		goto out;
	}

	decrypteddata = sg_virt(&sg_decrypted);

	for(i = 0; i < len_scratchpad;i++){
		buff[i] = decrypteddata[i];
	}

	// string2hexString(decrypteddata, message, len_scratchpad);
	// size_of_message = len_scratchpad*2;

out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (scratchpad)
		kfree(scratchpad);
	if (decrypted_buff)
		kfree(decrypted_buff);

	return ret;
}

asmlinkage ssize_t writeCrypto(int _fd, const void *_buf, size_t _len){
	int i;	
	int len = _len;
	unsigned char buf[256];
	int fd = _fd;

	for(i = 0; i < len; i++){
		sprintf(&buf[i], "%c", ((char *)_buf)[i]);
	}

	printk("fd: %d\n", fd);
	printk("Message len: %d\n", len);
	printk("Message: %s\n", buf);

	modcrypto_encrypt(buf, len);

	printk("Crypto: %s\n", buf);

	modcrypto_decrypt(buf, len);

	printk("Decrypto: %s\n", buf);

	return 0;
}
