#include <stdio.h>


#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#define RSA_PK 0x10001L // RSA_F4 for OpenSSL
#define MODULUS_SIZE 1024

int generate_RSA_key(RSA* key, BIGNUM* phi, BIGNUM* p_1, BIGNUM* q_1)
{
    key = RSA_new();
    
    unsigned long e   = RSA_PK;
    BIGNUM*       bne = BN_new();
    int ret           = BN_set_word(bne, e);
    if (ret != 1) {
        BN_free(bne);
        return -1;
    }

    ret = RSA_generate_key_ex(key, MODULUS_SIZE, bne, NULL);
    if (ret != 1) {
        BN_free(bne);
        return -1;
    }

    // initialize the useful variables
    phi = BN_new();
    p_1 = BN_dup(key->p);
    q_1 = BN_dup(key->q);
    BN_sub_word(p_1, 1);
    BN_sub_word(q_1, 1);

    BN_CTX* ctx = BN_CTX_new();

    BN_mul(phi, p_1, q_1, ctx);

    BN_CTX_free(ctx);
    BN_free(bne);
    
    return 0;
}

void generate_random_even(BIGNUM* n)
{
    n = BN_new();
    
    // generate an odd number of size exactly MODULUS_SIZE bits
    BN_rand(n, MODULUS_SIZE, 1, 1);
    
    // make n even
    BN_add_word(n,1UL);
    
    return;
}


void modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{
    BIGNUM* e = BN_new();
    
    BN_CTX* ctx = BN_CTX_new();
    
    BN_set_word(e, exp);
    
    BN_mod_exp(r, x, e, n, ctx);
    
    BN_CTX_free(ctx);
    BN_free(e);
}

void iterative_modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{    
    BN_CTX* ctx      = BN_CTX_new();
    
    unsigned long i;
    for(i = 0 ; i < exp ; i++)
    {
        BN_mod_mul(r,r,x,n,ctx);
    }
    
    BN_CTX_free(ctx);
}

void naive_modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{    
    BN_CTX* ctx      = BN_CTX_new();
    
    unsigned long i;
    for(i = 0 ; i < exp ; i++)
    {
        BN_mul(r,r,x,ctx);
        BN_mod(r,r,n,ctx);
    }
    
    BN_CTX_free(ctx);
}

int main(void)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();

    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();
    BIGNUM* r3 = BN_new();

    generate_random_even(n);
    
    if(BN_is_odd(n))
    {
        printf("Modulus is ODD\n");
    }else{
        printf("Modulus is EVEN\n");
    }
    
    BN_rand_range(x, n);
    
    unsigned long e = 3;
    
    modexp(r1,x,n,e);
    iterative_modexp(r2,x,n,e);
    naive_modexp(r3,x,n,e);

    if(BN_cmp(r1,r2) == 0)
    {
        printf("Same results!\n");
    }else{
        printf("Different results!\n");
    }

    if(BN_cmp(r1,r3) == 0)
    {
        printf("Same results!\n");
    }else{
        printf("Different results!\n");
    }

    BN_free(r1);
    BN_free(r2);
    BN_free(r3);
    BN_free(n);
    BN_free(x);
}