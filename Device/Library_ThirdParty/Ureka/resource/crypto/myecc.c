#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "NuMicro.h"

/* mbeTLS header files */
#include "ecp.h"
#include "ecdsa.h"
#include "sha256.h"
#include "pk.h"
#include "myecc.h"

#define CRYPTO_MAX_KEY_LEN 1024

/* timer ticks - 100 ticks per second */
volatile uint32_t g_tick_cnt;

void SysTick_Handler(void)
{
    g_tick_cnt++;
}

void enable_sys_tick(int ticks_per_second)
{
    g_tick_cnt = 0;
    SystemCoreClock = 96000000; /* HCLK is 96 MHz */
    if (SysTick_Config(SystemCoreClock / ticks_per_second))
    {
        /* Setup SysTick Timer for 1 second interrupts  */
        printf("Set system tick error!!\n");
    }
}

void start_timer0()
{
    /* Start TIMER0  */
    CLK->CLKSEL1 = (CLK->CLKSEL1 & (~CLK_CLKSEL1_TMR0SEL_Msk)) | CLK_CLKSEL1_TMR0SEL_HIRC;
    CLK->APBCLK0 |= CLK_APBCLK0_TMR0CKEN_Msk;                        /* enable TIMER0 clock                  */
    TIMER0->CTL = 0;                                                 /* disable timer                                  */
    TIMER0->INTSTS = (TIMER_INTSTS_TWKF_Msk | TIMER_INTSTS_TIF_Msk); /* clear interrupt status */
    TIMER0->CMP = 0xFFFFFE;                                          /* maximum time                                   */
    TIMER0->CNT = 0;                                                 /* clear timer counter                            */
    /* start timer */
    TIMER0->CTL = (11 << TIMER_CTL_PSC_Pos) | TIMER_ONESHOT_MODE | TIMER_CTL_CNTEN_Msk;
}

uint32_t get_timer0_counter()
{
    return TIMER0->CNT;
}

static int myrand(void *rng_state, unsigned char *output, size_t len)
{
#if !defined(__OpenBSD__)
    size_t i;

    if (rng_state != NULL)
        rng_state = NULL;

    for (i = 0; i < len; ++i)
        output[i] = rand();
#else
    if (rng_state != NULL)
        rng_state = NULL;

    arc4random_buf(output, len);
#endif /* !OpenBSD */

    return (0);
}

mbedtls_ecdsa_context generate_key_pair()
{
    mbedtls_ecdsa_context ecdsa;
    uint32_t u32Time;
    const char *pers = "ecdsa";
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    int ret = 0;

    mbedtls_ecdsa_init(&ecdsa);

    printf(" mbedtls ECDSA init done  \n\n");

    printf(" mbedtls ECDSA generate key       : ");
    if ((ret = mbedtls_ecdsa_genkey(&ecdsa, curve_info->grp_id, myrand, NULL)) == 0)
    {
        printf("passed1\n");
    }
    else
    {
        printf("failed! ret[%d]\n", ret);
        mbedtls_ecdsa_free(&ecdsa);
        // return ret;
    }

    printf(" mbedtls ECDSA key pair           : ");
    if ((ret = mbedtls_ecdsa_from_keypair(&ecdsa, &ecdsa)) == 0)
    {
        printf("passed2\n");
    }
    else
    {
        printf("failed! ret[%d]\n", ret);
        mbedtls_ecdsa_free(&ecdsa);
        // return ret;
    }

    return ecdsa;
}

size_t sign_message(const char *message, mbedtls_ecdsa_context key, unsigned char *signature)
{
    mbedtls_ecdsa_context ctx = key;
    const char *pers = "ecdsa";
    unsigned char hash[32];
    uint32_t u32Time;
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    size_t sig_len;
    int ret;

    if ((ret = mbedtls_sha256_ret((const unsigned char *)message, strlen(message), hash, 0)) != 0)
    {
        // std::cout << "Failed to hash message" << std::endl;
        printf("Failed to hash message\n");
    }

    printf("successfully hash message\n");

    ret = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, hash, curve_info->bit_size, signature, &sig_len, myrand, NULL);

    if (ret == 0)
    {
        printf("passed");
    }
    else
    {
        printf("failed! ret[%d]\n", ret);
        mbedtls_ecdsa_free(&ctx);
        // return ret;
    }

    // give sig_len to global variable
    printf("find out sig len locally %d\n", sig_len);

    return sig_len;
}

int verify_signature(const char *message, const unsigned char *signature, mbedtls_ecdsa_context ctx, size_t sig_len)
{
    // mbedtls_entropy_context entropy;
    // mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";
    unsigned char hash[32];
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    int ret;

    if ((ret = mbedtls_sha256_ret((const unsigned char *)message, strlen(message), hash, 0)) != 0)
    {
        // std::cout << "Failed to hash message" << std::endl;
        printf("Failed to hash message\n");
    }
    if (mbedtls_ecdsa_read_signature(&ctx, hash, curve_info->bit_size, (const unsigned char *)signature, sig_len) != 0)
    {
        ret = 0;
    }
    else
    {
        ret = 1;
    }

    return ret;
}

void pk_key_to_string(mbedtls_ecdsa_context key, char *ret_key)
{
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    int ret = 1;

    printf("first in pk key to string\n");

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        // cout << "mbedtls_pk_setup failed with error code " << ret << endl;
        printf("mbedtls_pk_setup failed with error code %d\n", ret);
        return;
    }

    mbedtls_ecp_keypair *keypair = (mbedtls_ecp_keypair *)pk.pk_ctx;
    *keypair = key;

    if ((ret = mbedtls_pk_write_key_pem(&pk, (unsigned char *)ret_key, 512)) != 0)
    {
        // cout << "mbedtls_pk_write_key_pem failed with error code " << ret << endl;
        printf("mbedtls_pk_write_key_pem failed with error code %d\n", ret);
        return;
    }

    // mbedtls_pk_free(&pk);

    return;
}

void pub_key_to_string(mbedtls_ecdsa_context key, char *ret_key)
{
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    printf("first in pub_key_to_string\n");

    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
    {
        // cout << "mbedtls_pk_setup failed with error code " << ret << endl;
        printf("mbedtls_pk_setup failed with error code %d\n", ret);
        return;
    }

    pk.pk_ctx = &key;

    if ((ret = mbedtls_pk_write_pubkey_pem(&pk, (unsigned char *)ret_key, 500)) != 0)
    {
        // cout << "mbedtls_pk_write_pubkey_pem failed with error code " << ret << endl;
        printf("mbedtls_pk_write_pubkey_pem failed with error code %d\n", ret);
        return;
    }

    // mbedtls_pk_free(&pk);

    return;
}

void byte_to_hex(unsigned char *bytes, int len, char *hex_str)
{
    for (int i = 0; i < len; i++)
    {
        sprintf(hex_str + 2 * i, "%02x", bytes[i]);
    }
}
void generate_sha256_hash_bytes(const char *message, char *ret_hash)
{
    // use mbedtls sha256
    unsigned char hash[32];
    if (mbedtls_sha256_ret((const unsigned char *)(message), strlen(message), hash, 0) != 0)
    {
        // cout << "Failed to hash message" << endl;
        printf("Failed to hash message\n");
    }

    byte_to_hex(hash, 32, ret_hash);

    // cout << "hash: " << ret_hash << endl;
    printf("hash: %s\n", ret_hash);
}

mbedtls_ecdsa_context turn_string_to_key(const char *pk, const char *pub)
{
    mbedtls_ecdsa_context key;
    mbedtls_ecdsa_init(&key);
    mbedtls_pk_context pk_ctx, pub_ctx;
    mbedtls_pk_init(&pk_ctx);
    mbedtls_pk_init(&pub_ctx);

    int ret = 1;

    if (strlen(pk) > 0)
    {
        ret = mbedtls_pk_parse_key(&pk_ctx, (const unsigned char *)pk, strlen(pk) + 1, NULL, 0);
        if (ret != 0)
        {
            // cout << "mbedtls_pk_parse_key failed with error code " << ret << endl;
            printf("mbedtls_pk_parse_key failed with error code %d\n", ret);
            return key;
        }

        if ((ret = mbedtls_ecp_group_copy(&key.grp, &mbedtls_pk_ec(pk_ctx)->grp)) != 0)
        {
            // cout << "mbedtls_ecp_group_copy failed with error code " << ret << endl;
            printf("mbedtls_ecp_group_copy failed with error code %d\n", ret);
            return key;
        }

        if ((ret = mbedtls_mpi_copy(&key.d, &mbedtls_pk_ec(pk_ctx)->d)) != 0)
        {
            // cout << "mbedtls_mpi_copy failed with error code " << ret << endl;
            printf("mbedtls_mpi_copy failed with error code %d\n", ret);
            return key;
        }
    }

    ret = 1;

    if (strlen(pub) > 0)
    {
        ret = mbedtls_pk_parse_public_key(&pub_ctx, (const unsigned char *)pub, strlen(pub) + 1);
        if (ret != 0)
        {
            // cout << "mbedtls_pk_parse_public_key failed with error code " << ret << endl;
            printf("mbedtls_pk_parse_public_key failed with error code %d\n", ret);
            return key;
        }

        if ((ret = mbedtls_ecp_copy(&key.Q, &mbedtls_pk_ec(pub_ctx)->Q)) != 0)
        {
            // cout << "mbedtls_ecp_copy failed with error code " << ret << endl;
            printf("mbedtls_ecp_copy failed with error code %d\n", ret);
            return key;
        }

        if ((ret = mbedtls_ecp_group_copy(&key.grp, &mbedtls_pk_ec(pub_ctx)->grp)) != 0)
        {
            // cout << "mbedtls_ecp_group_copy failed with error code " << ret << endl;
            printf("mbedtls_ecp_group_copy failed with error code %d\n", ret);
            return key;
        }
    }

    mbedtls_pk_free(&pk_ctx);
    mbedtls_pk_free(&pub_ctx);

    return key;
}