#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#define RSA_PK 0x10001L // RSA_F4 for OpenSSL
#define MODULUS_SIZE 512


void BN_printf(const BIGNUM* n)
{
    char* n_hex = BN_bn2hex(n);
    printf("%s",n_hex);
    
    free(n_hex);
}

void generate_random_even(BIGNUM* n)
{    
    // generate an odd number of size exactly MODULUS_SIZE bits
    BN_rand(n, MODULUS_SIZE, 1, 1);
    
    // make n even
    BN_add_word(n,1UL);
}


void modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{
    BIGNUM* e = BN_new();
    
    BN_CTX* ctx = BN_CTX_new();
    
    BN_set_word(e, exp);
    
    int ret = BN_mod_exp(r, x, e, n, ctx);
    
    if(!ret)
    {
        printf("Err in modexp\n");
        ERR_print_errors_fp(stdout);
        ERR_clear_error();
    }
    

    printf("Result (modexp, hex):\n");
    BN_printf(r);
    printf("\n");
    
    
    BN_CTX_free(ctx);
    BN_free(e);
}

void iterative_modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{    
    BIGNUM* tmp = BN_new();
        
    BN_CTX* ctx      = BN_CTX_new();
    BN_set_word(r,1UL);
    
    unsigned long i;
    int ret = 0;
    for(i = 0 ; i < exp ; i++)
    {
        ret = BN_mod_mul(tmp,r,x,n,ctx);
        if(!ret)
        {
            printf("Err in BN_mod_mul\n");
            break;
        }
        BN_swap(tmp,r);
    }
    
    printf("Result (iterative modexp, hex):\n");
    BN_printf(r);
    printf("\n");
        
    BN_CTX_free(ctx);
    BN_free(tmp);
}

void naive_modexp(BIGNUM* r, const BIGNUM* x, const BIGNUM* n, const unsigned long exp)
{    
    BIGNUM* tmp = BN_new();
    BN_CTX* ctx      = BN_CTX_new();
    
    BN_set_word(r,1UL);
    
    unsigned long i;
    int ret = 0;
    
    for(i = 0 ; i < exp ; i++)
    {
        ret = BN_mul(tmp,r,x,ctx);
        if(!ret)
        {
            printf("Err in BN_mul\n");
            break;
        }
        
        ret = BN_mod(r,tmp,n,ctx);
        if(!ret)
        {
            printf("Err in BN_mod\n");
            break;
        }
    }
    
    printf("Result (naive modexp, hex):\n");
    BN_printf(r);
    printf("\n");
        
    BN_CTX_free(ctx);
    BN_free(tmp);
}


void test(const BIGNUM* x, const BIGNUM* n, unsigned long e)
{
    int err = 0;
    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();
    BIGNUM* r3 = BN_new();
    
    if(BN_is_odd(n))
    {
        printf("Modulus is ODD\n");
    }else{
        printf("Modulus is EVEN\n");
    }    
    
    modexp(r1,x,n,e);
    iterative_modexp(r2,x,n,e);
    naive_modexp(r3,x,n,e);

    if(BN_cmp(r1,r2) == 0)
    {
        printf("OK: r1 == r2\n");
    }else{
        err++;
        printf("Error: r1 != r2\n");
    }

    if(BN_cmp(r1,r3) == 0)
    {
        printf("OK: r1 == r3\n");
    }else{
        err++;
        printf("Error: r1 != r3\n");
    }

    if(BN_cmp(r2,r3) == 0)
    {
        printf("OK: r2 == r3\n");
    }else{
        err++;
        printf("Error: r2 != r3\n");
    }

    if(err > 0){
        printf("Inconsistency in the modular exponentiation\n");
        printf("Modulus (hex):\n");
        BN_printf(n);
        printf("\nOperand (hex):\n");
        BN_printf(x);
        printf("\n");
    }

    BN_free(r1);
    BN_free(r2);
    BN_free(r3);
}

void check_random(unsigned long e)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();
    
    if(x == NULL){
        printf("Error\n");
    }
    if(n == NULL){
        printf("Error\n");
    }
          
    BN_rand(n, MODULUS_SIZE, 1, 0);  
    // generate_random_even(n);
    BN_rand_range(x, n);
    
    test(x,n,e);

    BN_free(n);
    BN_free(x);
}
 
void check_prime_modulus(unsigned long e)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();
    
    if(x == NULL){
        printf("Error\n");
    }
    if(n == NULL){
        printf("Error\n");
    }
          
    BN_generate_prime_ex(n, MODULUS_SIZE, 0, NULL, NULL, NULL);
    
    BN_rand_range(x, n);
    
    test(x,n,e);

    BN_free(n);
    BN_free(x);
}


void check_both_prime(unsigned long e)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();
    
    if(x == NULL){
        printf("Error\n");
    }
    if(n == NULL){
        printf("Error\n");
    }
          
    BN_generate_prime_ex(n, MODULUS_SIZE, 0, NULL, NULL, NULL);
    BN_generate_prime_ex(x, MODULUS_SIZE, 0, NULL, NULL, NULL);
    
    // make sure that n > x
    if(BN_cmp(n,x) < 0)
    {
        BIGNUM* tmp = x;
        x = n;
        n = tmp;
    }
        
    test(x,n,e);

    BN_free(n);
    BN_free(x);
}
 
void check_fixed_string(unsigned long e)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();


    // BN_hex2bn(&n, "EE9C3A7E8DABBD38278405E85516172987DFAAAAF0A89B372A301A77B2BAD9339C89B94D73D8007B8152A0EACFAFE31251860F624F78BE87E2CC508AAB7CD9AE524C7E1B3E02A3F19F518B101FF971231B175594D5174EDBA3D1C837D445E090FE2EDB7CEB106CE455E0300AFC23FF01E9A94C6C43B4D86156FD0296354B83E4");
    //
    // BN_hex2bn(&x, "81222C5A60105691B5FC4EB69E820161B2D40D3B928F7C9962AECC7B58579F0D866BCC637075BB9CA0CA2528A5704C726B4ED57CB1A8FD89DA0B2B3200CCFC1C0395A231F4F72AC151775CC7C98F711E4223729D399D83BD7195E5F234762426C5B610EF8A62FCCB3CC9E5A51BB97CAEAA0FEED373E46BB5D67C22B1A552CCFFC84F702A8F061777C5BB3D4EE97663E2C337E771A57014AC2FB2B5034C5D3B2E81629D6C54AB0CE54D9805F331779D37BA6F80FDCF1ABD82B7FCEDA98D81303C56C348350030B879414EB34AC41D09C885A0818289237C394CD95932D956F624E667A0856C63380DE73267B844B7BC01B9DA7D7E3FEBBB1577A1862F1FA8FF01");

    BN_hex2bn(&n, "E8F1D7B52CEC49B6A8BC0F3F3FEAF130FA3895ABD977A8343DB2166532812148");
        
    BN_hex2bn(&x, "C5DEBC3455A13AD6FBD4A44F2DD4D378B1795CE61E462AF9868D08B3AA578B6A8B94D122EC2D368DC31524D23D2E19481172A8184FA4EBBFC21F3EF41AB78081");
        
    test(x,n,e);        
    
    BN_free(n);
    BN_free(x);
}




int generate_extended_RSA_key(RSA* key, BIGNUM* phi, BIGNUM* p_1, BIGNUM* q_1)
{
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
    BN_copy(p_1,key->p);
    BN_copy(q_1,key->q);
    
    BN_sub_word(p_1, 1);
    BN_sub_word(q_1, 1);

    BN_CTX* ctx = BN_CTX_new();

    BN_mul(phi, p_1, q_1, ctx);

    BN_CTX_free(ctx);
    BN_free(bne);
    
    return 0;
}

int multiple_inverse_permutation(BIGNUM* x, const RSA* rsa, const BIGNUM* p_1, const BIGNUM* q_1, unsigned long order)
{
    BN_CTX* ctx      = BN_CTX_new();
    BIGNUM* bn_order = BN_new();
    BIGNUM* d_p      = BN_new();
    BIGNUM* d_q      = BN_new();
    BN_set_word(bn_order, order);

    int ret_p = 0, ret_q = 0;
    int err = 0;
        
    ret_p = BN_mod_exp(d_p, rsa->d, bn_order, p_1, ctx);
    if (ret_p != 1) {
        printf("BN_mod_exp(d, bn_order, p_1) failed, should not happen\n");
        ERR_print_errors_fp(stdout);
        ERR_clear_error();
        err++;
    } else if (BN_is_zero(d_p)) {
        printf("d_p == 0, should not happen\n");
        err++;
    }

    ret_q = BN_mod_exp(d_q, rsa->d, bn_order, q_1, ctx);
    if (ret_q != 1) {
        printf("BN_mod_exp(d, bn_order, q_1) failed, should not happen\n");
        ERR_print_errors_fp(stdout);
        ERR_clear_error();
        err++;
    } else if (BN_is_zero(d_q)) {
        printf("d_q == 0, should not happen\n");
        err++;
    }
    // BIGNUM* y_p = BN_new();
    // BIGNUM* y_q = BN_new();
    // BIGNUM* h   = BN_new();
    // BIGNUM* y   = BN_new();
    //
    // BN_mod_exp(y_p, x, d_p, rsa->p, ctx);
    // BN_mod_exp(y_q, x, d_q, rsa->q, ctx);
    //
    // BN_mod_sub(h, y_p, y_q, rsa->p, ctx);
    // BN_mod_mul(h, h, rsa->iqmp, rsa->p, ctx);
    //
    // BN_mul(y, h, rsa->q, ctx);
    // BN_add(y, y, y_q);
 
 
    BN_free(bn_order);
    BN_free(d_p);
    BN_free(d_q);
    // BN_free(y_p);
    // BN_free(y_q);
    // BN_free(h);
    // BN_free(y);
    BN_CTX_free(ctx);   
    
    return err;
}

void test_permutation()
{
    RSA* rsa = RSA_new();;
    BIGNUM* phi = BN_new();
    BIGNUM* p_1 = BN_new();
    BIGNUM* q_1 = BN_new();
    
    generate_extended_RSA_key(rsa, phi, p_1, q_1);
        
    BIGNUM* x = BN_new();
    
    BN_rand_range(x, rsa->n);
    
    int ret = multiple_inverse_permutation(x,rsa, p_1, q_1, 100);
    
    if (ret > 0){
        printf("\n===========================================================\n");
        printf("Error in the exponent computation:\n");

        printf("Key:\n");
        printf("N:\n");
        BN_printf(rsa->n);
        printf("\nd:\n");
        BN_printf(rsa->d);
        printf("\np-1:\n");
        BN_printf(p_1);
        printf("\nq-1:\n");
        BN_printf(q_1);
        printf("\n\n");
        
        printf("Trying to reproduce the error ...\n");
        
        printf("For p-1:\n");
        test(rsa->d,p_1,100);

        printf("\nFor q-1:\n");
        test(rsa->d,q_1,100);

    }
    BN_free(x);
    BN_free(phi);
    BN_free(p_1);
    BN_free(q_1);
    RSA_free(rsa);
}




int main(void)
{
    ERR_load_crypto_strings();

    for(unsigned long i = 0; i < 20; ++i){
        // check_fixed_string(100);
        test_permutation();
    }
    
    // check_fixed_string(100);
    
    // for(unsigned long i = 0; i < 10; ++i)
    // {
    //     check_random(100);
    //     printf("\n\n");
    // }
    
    // for(unsigned long i = 0; i < 2; ++i)
    // {
    //     check_both_prime(100);
    //     printf("\n\n");
    // }

}