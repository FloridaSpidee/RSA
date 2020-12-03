#pragma once
#ifndef RSA_H
#define RSA_H
#include<iostream>
#include<vector>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#include<limits.h>

#define FACTOR_DIGITS 100
#define EXPONENT_MAX RAND_MAX
#define BUF_SIZE 1024

#define BIGNUM_CAPACITY 20

#define RADIX 4294967296UL
#define HALFRADIX 2147483648UL

#define ACCURACY 20
#define MAX(a,b) ((a) > (b) ? (a) : (b))

typedef unsigned int word;

typedef struct _bignum {
	int length;
	int capacity;
	word* data;
} bignum;



class RSA
{
private:
	bignum* p, * q, * n, * phi, * e, * d, * bbytes, * shift, * temp1, * temp2, * encoded;
	int* decoded, i, bytes, len;
	char* buffer,*cdecoded;
	FILE* f;
	bignum* bignum_init();//大数初始化
	int bignum_iszero(bignum* b);
	int bignum_isnonzero(bignum* b);
	void bignum_copy(bignum* source, bignum* dest);
	void bignum_fromstring(bignum* b, char* string);
	void bignum_fromint(bignum* b, unsigned int num);
	

	int bignum_equal(bignum* b1, bignum* b2);
	int bignum_greater(bignum* b1, bignum* b2);
	int bignum_less(bignum* b1, bignum* b2);
	int bignum_geq(bignum* b1, bignum* b2);
	int bignum_leq(bignum* b1, bignum* b2);

	void bignum_iadd(bignum* source, bignum* add);
	void bignum_add(bignum* result, bignum* b1, bignum* b2);
	void bignum_isubtract(bignum* source, bignum* add);
	void bignum_subtract(bignum* result, bignum* b1, bignum* b2);
	void bignum_imultiply(bignum* source, bignum* add);
	void bignum_multiply(bignum* result, bignum* b1, bignum* b2);
	void bignum_idivide(bignum* source, bignum* div);
	void bignum_idivider(bignum* source, bignum* div, bignum* remainder);
	void bignum_remainder(bignum* source, bignum* div, bignum* remainder);
	void bignum_imodulate(bignum* source, bignum* modulus);
	void bignum_divide(bignum* quotient, bignum* remainder, bignum* b1, bignum* b2);

	void bignum_modpow(bignum* base, bignum* exponent, bignum* modulus, bignum* result);
	void bignum_gcd(bignum* b1, bignum* b2, bignum* result);
	void bignum_inverse(bignum* a, bignum* m, bignum* result);
	int bignum_jacobi(bignum* ac, bignum* nc);
	int solovayPrime(int a, bignum* n);
	int probablePrime(bignum* n, int k);
	void randPrime(int numDigits, bignum* result);
	void randExponent(bignum* phi, int n, bignum* result);

	void bignum_print(bignum* b);//大数打印
	void bignum_deinit(bignum* b);//大数删除

	void cptMaxNum();

	int readFile(FILE* fd, char** buffer, int bytes);
	int readString(char* source, char** buffer, int bytes);

	void enCode(bignum* m, bignum* e, bignum* n, bignum* result);
	void deCode(bignum* c, bignum* d, bignum* n, bignum* result);
	bignum* encodeMessage(int len, int bytes, char* message, bignum* exponent, bignum* modulus);
	char* decodeMessage(int len, int bytes, bignum* cryptogram, bignum* exponent, bignum* modulus);
public:
	RSA();
	//~RSA();
	void generateKeys();       //生成公钥和私钥 
	//string encode(string signature);//加密签名 
	//string decode(string code, vector<int> publicKey);//解密签名
	bignum* getN();
	bignum* getE();
	bignum* getD();
	void setN(char *n);
	void setE(char *e);
	void setD(char *d);

	void printPublicKey();
	void printPrivateKey();
	bignum* encode(char *plainText);
	char* decode(char * cipherText);

	int encodeFile(const char* path);
	void decodeFile();
	
};

#endif // RSA_H