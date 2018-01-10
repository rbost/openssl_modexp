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
        char* n_hex = BN_bn2hex(n);
        char* x_hex = BN_bn2hex(x);

        printf("Inconsistency in the modular exponentiation\n");
        printf("Modulus (hex):\n");
        printf("%s",n_hex);
        printf("\nOperand (hex):\n");
        printf("%s",x_hex);
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
 
void check_fixed_string(unsigned long e)
{
    BIGNUM* x = BN_new();
    BIGNUM* n = BN_new();


    BN_hex2bn(&n, "EE9C3A7E8DABBD38278405E85516172987DFAAAAF0A89B372A301A77B2BAD9339C89B94D73D8007B8152A0EACFAFE31251860F624F78BE87E2CC508AAB7CD9AE524C7E1B3E02A3F19F518B101FF971231B175594D5174EDBA3D1C837D445E090FE2EDB7CEB106CE455E0300AFC23FF01E9A94C6C43B4D86156FD0296354B83E4");
        
    BN_hex2bn(&x, "81222C5A60105691B5FC4EB69E820161B2D40D3B928F7C9962AECC7B58579F0D866BCC637075BB9CA0CA2528A5704C726B4ED57CB1A8FD89DA0B2B3200CCFC1C0395A231F4F72AC151775CC7C98F711E4223729D399D83BD7195E5F234762426C5B610EF8A62FCCB3CC9E5A51BB97CAEAA0FEED373E46BB5D67C22B1A552CCFFC84F702A8F061777C5BB3D4EE97663E2C337E771A57014AC2FB2B5034C5D3B2E81629D6C54AB0CE54D9805F331779D37BA6F80FDCF1ABD82B7FCEDA98D81303C56C348350030B879414EB34AC41D09C885A0818289237C394CD95932D956F624E667A0856C63380DE73267B844B7BC01B9DA7D7E3FEBBB1577A1862F1FA8FF01");
        
    test(x,n,e);        
    
    BN_free(n);
    BN_free(x);
}

int main(void)
{
    check_fixed_string(100);
    
    
    for(unsigned long i = 0; i < 10; ++i)
    {
        check_random(100);
        printf("\n\n");
    }
}