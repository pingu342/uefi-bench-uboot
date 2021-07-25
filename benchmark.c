#include <efi.h>
#include <efilib.h>
#include <libsmbios.h>
#include <string.h>
#include <u-boot/sha1.h>
#include <u-boot/sha256.h>
#include <u-boot/rsa-mod-exp.h>

static void disable_irq(void)
{
	//asm volatile("isb; msr DAIFSet, #15");
}

static void enable_irq(void)
{
	//asm volatile("isb; msr DAIFClr, #15");
}

static uint32_t ctr_freq(void)
{
	uint32_t freq;
	asm volatile ("isb; mrs %0, cntfrq_el0" : "=r" (freq));
	return freq;
}

static inline uint64_t read_ctr(void)
{
	uint64_t val;
//	asm volatile("mrs %0, pmccntr_el0" : "=r"(val));
	asm volatile ("isb; mrs %0, cntvct_el0" : "=r" (val));
	return val;
}

#define SHA1_HASH_SIZE (20)
#define SHA256_HASH_SIZE (32)
#define RSA2048_SIGN_SIZE (256)

static const unsigned char testdata1[] = "abc";
static const unsigned char testdata1_sha1_hash[] = {
	0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,
	0x9C,0xD0,0xD8,0x9D
};
static const unsigned char testdata1_sha256_hash[] = {
	0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
	0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
};

static unsigned char sha1_hash[SHA1_HASH_SIZE];
static unsigned char sha256_hash[SHA256_HASH_SIZE];

int printf(const char *fmt, ...)
{
	return 0;
}

static void print_data(const char *msg, unsigned char *data, int len)
{
	int i;
	Print(L"%a:", msg);
	for (i=0; i<len; i++)
	{
		Print(L" %02x", data[i]);
	}
	Print(L"\n");
}

static int comp_data(const unsigned char *d1, const unsigned char *d2, int len)
{
	int i;
	for (i=0; i<len; i++)
	{
		if (d1[i] != d2[i])
		{
			return i;
		}
	}
	return i;
}

int memcmp(const void *d1, const void *d2, size_t len)
{
	return comp_data((const unsigned char *)d1, \
			(const unsigned char *)d2, len) == len ? \
			0 : 1;
}

static void sha1(uint64_t *t)
{
	uint32_t freq = ctr_freq();
	uint64_t start, elaps;
	disable_irq();
	start = read_ctr();
	{
		sha1_context ctx;
		sha1_starts(&ctx);
		sha1_update(&ctx, testdata1, sizeof(testdata1)-1);
		sha1_finish(&ctx, sha1_hash);
	}
	elaps = read_ctr() - start;
	enable_irq();
	if (*t > elaps)
		*t = elaps;
	print_data("sha1 out", sha1_hash, SHA1_HASH_SIZE);
	Print(L"sha1 check: %a\n", comp_data(sha1_hash, testdata1_sha1_hash, SHA1_HASH_SIZE) == SHA1_HASH_SIZE ? "OK" : "NG");
	Print(L"sha1 elaps: %ld (%ldusec)\n", elaps, (elaps * 1000000 / freq));
}

static void sha256(uint64_t *t)
{
	uint32_t freq = ctr_freq();
	uint64_t start, elaps;
	disable_irq();
	start = read_ctr();
	{
		sha256_context ctx;
		sha256_starts(&ctx);
		sha256_update(&ctx, testdata1, sizeof(testdata1)-1);
		sha256_finish(&ctx, sha256_hash);
	}
	elaps = read_ctr() - start;
	enable_irq();
	if (*t > elaps)
		*t = elaps;
	print_data("sha256 out", sha256_hash, SHA256_HASH_SIZE);
	Print(L"sha256 check: %a\n", comp_data(sha256_hash, testdata1_sha256_hash, SHA256_HASH_SIZE) == SHA256_HASH_SIZE ? "OK" : "NG");
	Print(L"sha256 elaps: %ld (%ldusec)\n", elaps, (elaps * 1000000 / freq));
}


static const char *modulu_data = "da bf aa e9 b5 5c bd cc dc 32 f2 22 62 b0 c4 61 c0 82 f4 0f a9 ba de 9f 6f a2 6b 42 cd 41 55 b5 1c 3b cc 87 23 36 ca e8 08 86 6c ae 82 db 37 1e 1d ab f6 31 05 49 ba f6 a8 b1 21 35 89 99 1a 62 46 78 52 98 99 d4 6b 93 ba c6 20 75 91 b1 bb 8b 94 26 da 0c 19 b1 25 bc b2 65 9c 1a 42 e1 16 f0 a3 25 9f 49 a6 a8 23 f6 8d e8 eb 32 c4 42 66 36 88 7d 47 77 bb 69 ed 0b 73 d2 db 8f 30 7a f1 1b 82 6e fc 61 2a 05 aa c7 f4 b0 39 5d a1 71 a1 dc ad bb db c6 9a 51 43 4b 32 7f d9 50 04 a5 ba de 12 69 40 78 e1 1d ed 0a a4 52 a0 48 90 5c 0c a3 a1 3a 8b 1f e0 88 a8 85 5c b0 6a e1 93 08 44 f9 fa 77 d8 80 ca 23 8d 08 cb f9 12 97 e5 89 51 64 e6 4e 83 5e d8 12 df b2 28 40 0c 86 b7 dc 1a af 06 03 ed 9a 50 8c f2 70 3b a6 39 b6 19 66 1d ce 9d 44 22 e8 49 24 e8 91 10 51 5b 81 c8 e9 75 4b";
static const char *public_exponent_data = "00 00 00 00 00 01 00 01";
static const char *rr_data = "be bd 29 73 58 20 38 b2 2e b1 ca a2 b8 29 fd 34 59 e7 df 83 23 3b a5 6d 75 d7 89 45 d1 24 3d 34 28 60 60 30 c9 2f f5 5b 18 4d 87 ac 38 6f 32 7d be 37 65 dd 17 75 ed 06 a2 ef 56 46 be 2a 5f 0e e8 ec d6 28 05 5e 55 74 6d 87 01 a9 05 93 25 d0 b8 85 7d 72 68 69 0a 20 6a 60 fa d2 de de e1 14 20 bd d2 bd 5a 1e d3 9e 30 c4 42 3c a9 e0 89 e7 f5 07 e3 7a 5e 61 01 ff e5 74 7c 36 83 81 bf 35 f9 0e aa a4 f5 eb 2a 85 94 80 33 d5 93 c7 4d ce 4e 53 71 87 ca 8a 4d 96 8a 99 da db d6 36 50 15 64 f9 b1 76 cd 3c 0d 40 4b c4 e9 04 0c 72 e1 51 ac 31 37 a2 65 14 db 6a b9 10 86 df e4 a0 cf 13 99 92 f2 0d cf 57 b6 db 99 4f 96 88 0d bc 66 d7 02 c1 8c 9e 68 7c c3 51 e4 86 60 ea 0d 87 aa 50 0e 49 f6 1b 4f 00 2d 03 a8 fc 92 97 73 c1 85 b9 92 79 f0 2c 64 b4 3e d6 ec 2a 7f 27 56 25 6e 73";
static const unsigned int n0inv = 684430237;
static const char *sign_data = "6d 0e d6 8b 1d 37 f8 0a 50 57 9d b0 c4 b3 af ac 47 19 92 6d 0b 98 29 ac 23 8d 27 ea b6 c3 86 69 95 76 1e 80 47 70 88 56 5e 85 60 f8 09 bc f1 ff 27 c2 3b bd 3f 06 ae 99 2e 87 35 af 9a 91 b6 0e d8 0b 4c b7 97 37 4f 5c c5 90 66 1f e3 e8 a0 2d d9 5a b5 ce 09 3d 95 11 68 6c 2e f8 85 64 6c 5c 52 1b 70 48 98 28 5e 94 d6 0d 0c e5 69 72 14 65 34 d6 b7 59 6b 29 4c 46 6e 4f c6 df c5 7b 74 7f 91 a8 f2 6b 95 32 db e3 a3 bc 3b 3b e0 b8 33 9e 1e 53 f9 79 a0 62 4d d3 9b 02 80 7d f6 c2 8c d1 5c e7 9c 66 9a f2 bf 76 2d 6b 5b 6b be 96 f3 6d 87 c5 9a 8b 5a 5e 9d 4b 23 ca e0 40 44 c9 24 39 a6 a3 ce 12 0d 3c e5 6d cc ab 37 fb 4e f0 b5 b5 25 87 93 35 9e 7a 17 99 83 5e 4e 56 06 7f c5 b9 d2 59 12 11 a3 de ae ff 22 14 15 93 05 ac 40 de 36 93 bf 42 f0 1f de 5a a6 91 e9 47 9e 85 84 45";
static const char *out_data = "00 01 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 19 1c b1 21 51 4f ef 57 91 a9 58 2e 9b 23 bc 0e 71 88 13 2c";

static unsigned char modulus[RSA2048_SIGN_SIZE];
static unsigned char public_exponent[8];
static unsigned char rr[RSA2048_SIGN_SIZE];
static unsigned char sign[RSA2048_SIGN_SIZE];
static unsigned char out[RSA2048_SIGN_SIZE];

static int chr2int(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return 10 + c - 'a';
	}

	return -1;
}
static int str2bin(unsigned char *o, const char *i)
{
	int d1, d2;
	unsigned char *p = o;
	while (*i)
	{
		d1 = chr2int(*i);
		i++;
		if (d1 >= 0)
		{
			d2 = chr2int(*i);
			i++;
			if (d2 < 0)
			{
				return -1;
			}
			*p = (d1 << 4) + d2;
			p++;
		}
	}
	return p - o;
}

static void rsa2048(uint64_t *t)
{
	uint32_t freq = ctr_freq();
	uint64_t start, elaps;
	struct key_prop prop;
	uint8_t buf[RSA2048_SIGN_SIZE];
	int len;

	len = str2bin(sign, sign_data);
#ifdef ENABLE_LOG
	print_data("sign", sign, len);
#endif
	len = str2bin(out, out_data);
#ifdef ENABLE_LOG
	print_data("out", out, len);
#endif
	len = str2bin(modulus, modulu_data);
#ifdef ENABLE_LOG
	print_data("modulus", modulus, len);
#endif
	len = str2bin(rr, rr_data);
#ifdef ENABLE_LOG
	print_data("rr", rr, len);
#endif
	len = str2bin(public_exponent, public_exponent_data);
#ifdef ENABLE_LOG
	print_data("public_exponent", public_exponent, len);
#endif

	disable_irq();
	start = read_ctr();
	{
		prop.rr = rr;
		prop.modulus = modulus;
		prop.public_exponent = public_exponent;
		prop.n0inv = n0inv;
		prop.num_bits = RSA2048_SIGN_SIZE * 8;
		prop.exp_len = len;
		rsa_mod_exp_sw(sign, RSA2048_SIGN_SIZE, &prop, buf);
	}
	elaps = read_ctr() - start;
	enable_irq();
	
	if (*t > elaps)
		*t = elaps;

	print_data("rsa2048 out", buf, RSA2048_SIGN_SIZE);
	Print(L"rsa2048 check: %a\n", comp_data(buf, out, RSA2048_SIGN_SIZE) == RSA2048_SIGN_SIZE ? "OK" : "NG");
	Print(L"rsa2048 elaps: %ld (%ldusec)\n", elaps, (elaps * 1000000 / freq));
}

static void bench(void (*f)(uint64_t *t), int n)
{
	int i;
	uint32_t freq = ctr_freq();
	uint64_t elaps = (uint64_t)-1;
	for (i=0; i<n; i++)
	{
		f(&elaps);
	}
	Print(L"--- Minimum: %lu (%ldusec) ---\n", elaps, elaps * 1000000 / freq);
}

void benchmark(void)
{
	uint32_t freq = ctr_freq();
	Print(L"ctr_freq: %u\n", freq);
#if 0
	{
		/* Output log every secound. */
		uint32_t sec = 0;
		while (1)
		{
			uint64_t c = read_ctr();
			if (sec < c/freq)
				Print(L"%lx %d\n", c, c/freq);
			sec = c/freq;
		}
	}
#endif
	Print(L"\nbenchmark_main\n");
	bench(sha1, 1);
	bench(sha256, 1);
	bench(rsa2048, 1);
}

