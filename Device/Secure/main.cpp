/**************************************************************************/ /**
                                                                              * @file     main.c
                                                                              * @version  V1.00
                                                                              * @brief    Secure sample code for TrustZone
                                                                              *
                                                                              * @copyright SPDX-License-Identifier: Apache-2.0
                                                                              * @copyright Copyright (C) 2020 Nuvoton Technology Corp. All rights reserved.
                                                                              ******************************************************************************/

#include "NuMicro.h" /* Device header */
#include "partition_M2354.h"
#include <arm_cmse.h>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
// library for memcpy
#include <stdio.h>
#include <string.h>

#include "current_session.hpp"
#include "environment.hpp"
#include "jsonBuild.hpp"
#include "message.hpp"
#include "other_device.hpp"
#include "r_ticket.hpp"
#include "this_device.hpp"
#include "this_person.hpp"
#include "u_ticket.hpp"
#include <map>
#include <string>

// #include "msg_generator_r_ticket.hpp"

#include "device_controller.hpp"

#define NEXT_BOOT_BASE 0x10040000
#define JUMP_HERE 0xe7fee7ff /* Instruction Code of "B ." */

#define KEY_LENGTH 256
#define PRNG_KEY_SIZE PRNG_KEY_SIZE_256
#define CURVE_P_SIZE CURVE_KO_256
// #define BLE

// AES GCM
#define GCM_MODE (AES_MODE_GCM << CRPT_AES_CTL_OPMODE_Pos)
#define GHASH_MODE (AES_MODE_GHASH << CRPT_AES_CTL_OPMODE_Pos)
#define CTR_MODE (AES_MODE_CTR << CRPT_AES_CTL_OPMODE_Pos)

#define DMAEN CRPT_AES_CTL_DMAEN_Msk
#define DMALAST CRPT_AES_CTL_DMALAST_Msk
#define DMACC CRPT_AES_CTL_DMACSCAD_Msk
#define START CRPT_AES_CTL_START_Msk
#define FBIN CRPT_AES_CTL_FBIN_Msk
#define FBOUT CRPT_AES_CTL_FBOUT_Msk
#define GCM_PBLOCK_SIZE                                                        \
    128 /* NOTE: This value must be 16 bytes alignment. This value must > size \
           of A */
#define MAX_GCM_BUF 128

// BLE
#ifdef BLE
#define RXBUFSIZE 20
#endif

#define VOTER_SIZE 30

__ALIGNED(4)
uint8_t g_au8Out[MAX_GCM_BUF];

extern "C"
{

    extern void my_sha256(char *input, uint32_t *hash);
    extern int generate_keys(char *d, char *Qx, char *Qy);
    extern int sign_message(const char *msg, char *d, char *R, char *S);
    extern int verify_signature(char *Qx, char *Qy, char *R, char *S,
                                const char *msg);
    extern int generate_secret_keys(char *d, char *Qx, char *Qy, char *k);
    extern int gcm_encrypt(char *key, char *iv, char *A, char *P, uint8_t *C,
                           uint32_t *plen_aligned, uint32_t *plen);
    extern int gcm_decrypt(char *key, char *iv, char *A, uint8_t *C, char *P,
                           uint32_t C_len);
    void string2hex(const char *input, char *output);
    extern uint32_t FMC_Read(uint32_t u32Addr);
    extern int32_t FMC_Write(uint32_t u32Addr, uint32_t u32Data);
    extern int32_t FMC_Erase(uint32_t u32PageAddr);
    extern int KeyStore_Read(uint32_t flash_addr, char buffer[]);
    extern int32_t Write_KeyStore_Flash_ID(char key[], int key_len,
                                           uint32_t flash_addr);
    extern int32_t ToLittleEndian(uint8_t *pbuf, uint32_t u32Size);

#ifdef BLE
    extern void BLE_SendCommand(const char *cmd);
    extern void BLE_SendMessage(const char *msg);
    extern void BLE_Init(void);
#endif
}

string gcm_gen_iv();
string byte_to_hex(unsigned char *bytes, int len);
string hex_to_byte(string hex_str);
string generate_random_str(int bytes_num);
string add_that_json(const string &input);
void remove_something(char *msg);

// FSM, before, after, and during

enum class VOTING_STATE
{
    BEFORE_VOTING,
    DURING_VOTING,
    // IDLE_VOTING,
};

//
DeviceController iot_device =
    DeviceController(this_device::IOT_DEVICE, "iot_device");

VOTING_STATE voting_state = VOTING_STATE::BEFORE_VOTING;

vector<pair<string, int>> voting_candidates;
pair<string, bool> voting_voters[VOTER_SIZE];

int candidate_num = 0;
int voter_num = 0;
#ifdef BLE
extern "C" char *received_msg;
extern "C" volatile int read_flag;
extern "C" volatile uint32_t g_u32comRtail;
#else
char *received_msg;
volatile int read_flag;
volatile uint32_t g_u32comRtail;
#endif

using namespace std;

static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz"
                                   "0123456789+/";

/* typedef for NonSecure callback functions */
typedef __NONSECURE_CALL int32_t (*NonSecure_funcptr)(char);
typedef __NONSECURE_CALL int32_t (*NonSecure_funcptr_void)(int);
typedef int32_t (*Secure_funcptr)(void);

extern "C"
{
    static NonSecure_funcptr pfNonSecure_BLE_send = (NonSecure_funcptr)NULL;
    static NonSecure_funcptr_void pfNonSecure_Free = (NonSecure_funcptr_void)NULL;

    __NONSECURE_ENTRY
    int32_t Secure_Free(NonSecure_funcptr *callback);
    __NONSECURE_ENTRY
    int32_t Secure_BLE_callback(NonSecure_funcptr *callback);
    __NONSECURE_ENTRY
    int32_t Secure_func(char *msg);
    __NONSECURE_ENTRY
    int32_t Secure_receive(char *msg);

    /*----------------------------------------------------------------------------
      Secure functions exported to NonSecure application
      Must place in Non-secure Callable
     *----------------------------------------------------------------------------*/
    __NONSECURE_ENTRY
    int32_t Secure_func(char *msg)
    {
        // iot_device.recv_xxx_message_ble();
        printf("%s", msg);
        // char *msg = "Hello from Secure!";
        // for (int i = 0; i < 10; i++) {
        //     pfNonSecure_BLE_send(msg[i]);
        // }

        return 1;
    }

    __NONSECURE_ENTRY
    int32_t Secure_Free(NonSecure_funcptr *callback)
    {
        pfNonSecure_Free = (NonSecure_funcptr_void)cmse_nsfptr_create(callback);
        return 0;
    }

    __NONSECURE_ENTRY
    int32_t Secure_BLE_callback(NonSecure_funcptr *callback)
    {
        pfNonSecure_BLE_send = (NonSecure_funcptr)cmse_nsfptr_create(callback);
        return 0;
    }

    __NONSECURE_ENTRY
    int32_t Secure_receive(char *msg)
    {
        // printf("Secure received: %s\n", msg);
        iot_device.recv_xxx_message_ble(msg);
        return 1;
    }
}

void SYS_Init(void);
void DEBUG_PORT_Init(void);
void Boot_Init(uint32_t u32BootBase);

void BLE_SendMessage(const char *msg)
{
    int len = strlen(msg);
    printf("%s", msg);
    // for (int i = 0; i < len; i++) {
    //     printf("%c", msg[i]);
    //     pfNonSecure_BLE_send(msg[i]);
    // }
}

/*----------------------------------------------------------------------------
    Boot_Init function is used to jump to next boot code.
 *----------------------------------------------------------------------------*/
void Boot_Init(uint32_t u32BootBase)
{
    NonSecure_funcptr fp;

    /* SCB_NS.VTOR points to the Non-secure vector table base address. */
    SCB_NS->VTOR = u32BootBase;

    /* 1st Entry in the vector table is the Non-secure Main Stack Pointer. */
    __TZ_set_MSP_NS(
        *((uint32_t *)SCB_NS->VTOR)); /* Set up MSP in Non-secure code */

    /* 2nd entry contains the address of the Reset_Handler (CMSIS-CORE) function
     */
    fp = ((NonSecure_funcptr)(*(((uint32_t *)SCB_NS->VTOR) + 1)));

    /* Clear the LSB of the function address to indicate the function-call
       will cause a state switch from Secure to Non-secure */
    fp = cmse_nsfptr_create(fp);

    /* Check if the Reset_Handler address is in Non-secure space */
    if (cmse_is_nsfptr(fp) && (((uint32_t)fp & 0xf0000000) == 0x10000000))
    {
        printf("[M2354] Execute non-secure code ...\n");
        fp(0); /* Non-secure function call */
    }
    else
    {
        /* Something went wrong */
        printf("[M2354] No code in non-secure region!\n");
        printf("[M2354] CPU will halted at non-secure state\n");

        /* Set nonsecure MSP in nonsecure region */
        __TZ_set_MSP_NS(NON_SECURE_SRAM_BASE + 512);

        /* Try to halted in non-secure state (SRAM) */
        M32(NON_SECURE_SRAM_BASE) = JUMP_HERE;
        fp = (NonSecure_funcptr)(NON_SECURE_SRAM_BASE + 1);
        fp(0);

        while (1)
            ;
    }
}

/*----------------------------------------------------------------------------
  Main function
 *----------------------------------------------------------------------------*/
int main(void)
{
    SYS_UnlockReg();

    SYS_Init();

    /* UART is configured as debug port */
    DEBUG_PORT_Init();
    SYS_ResetModule(UART1_RST);
    /* Initialize key store */
    KS_Open();

    // 打開 FMC
    FMC_Open();

    NVIC_EnableIRQ(CRPT_IRQn);
    ECC_ENABLE_INT(CRPT);
    AES_ENABLE_INT(CRPT);
    UART_Open(UART0, 115200);

#ifdef BLE
    /* Configure UART1 and set UART1 baud rate */
    UART_Open(UART1, 9600);
    /* Enable UART1 RDA interrupt */
    NVIC_EnableIRQ(UART1_IRQn);
    UART_EnableInt(UART1, UART_INTEN_RDAIEN_Msk);
    printf("\n\nCPU @ %dHz\n", SystemCoreClock);
    printf("\nBLE UART Sample Program\n");
    /* Initialize BLE module */
    BLE_Init();

    // Send initial message
    BLE_SendMessage("Hello from M2354!\r\n");
#endif

    // DeviceController iot_device =
    //     DeviceController(this_device::IOT_DEVICE, "iot_device");

    // while (1) {
    //     iot_device.recv_xxx_message_ble();
    // }

    printf("[M2354] Secure is running ...\n");

    /* Init and jump to Non-secure code */
    Boot_Init(NEXT_BOOT_BASE);

    do
    {
        __WFI();
    } while (1);
}

void SYS_Init(void)
{
    /* This should be check if it is neccessary */
    /* Set PF multi-function pins for XT1_OUT(PF.2) and XT1_IN(PF.3) */
    SYS->GPF_MFPL = (SYS->GPF_MFPL & (~SYS_GPF_MFPL_PF2MFP_Msk)) |
                    SYS_GPF_MFPL_PF2MFP_XT1_OUT;
    SYS->GPF_MFPL = (SYS->GPF_MFPL & (~SYS_GPF_MFPL_PF3MFP_Msk)) |
                    SYS_GPF_MFPL_PF3MFP_XT1_IN;

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init System Clock */
    /*---------------------------------------------------------------------------------------------------------*/

    /* Enable HIRC and HXT clock */
    CLK_EnableXtalRC(CLK_PWRCTL_HIRCEN_Msk | CLK_PWRCTL_HXTEN_Msk);

    /* Wait for HIRC and HXT clock ready */
    CLK_WaitClockReady(CLK_STATUS_HIRCSTB_Msk | CLK_STATUS_HXTSTB_Msk);

    /* Enable HIRC and HXT clock */
    CLK_EnableXtalRC(CLK_PWRCTL_LIRCEN_Msk);

    /* Wait for HIRC and HXT clock ready */
    CLK_WaitClockReady(CLK_STATUS_LIRCSTB_Msk);

    /* Set core clock to 96MHz */
    CLK_SetCoreClock(96000000);

    /* Enable UART0 module clock */
    /* Enable UART1 module clock */
    CLK_EnableModuleClock(UART0_MODULE);
    CLK_EnableModuleClock(UART1_MODULE);
    CLK_EnableModuleClock(UART2_MODULE);

    /* Enable CRYPTO module clock */
    CLK_EnableModuleClock(CRPT_MODULE);

    /* Enable Key Store module clock */
    CLK_EnableModuleClock(KS_MODULE);

    /* Select UART0 module clock source as HIRC and UART0 module clock divider
     * as 1 */
    CLK_SetModuleClock(UART0_MODULE, CLK_CLKSEL2_UART0SEL_HIRC,
                       CLK_CLKDIV0_UART0(1));

    /* Select UART1 module clock source as HXT and UART module clock divider as
     * 1 */
    CLK_SetModuleClock(UART1_MODULE, CLK_CLKSEL2_UART1SEL_HXT,
                       CLK_CLKDIV0_UART1(1));

    /* Select UART2 module clock source as HXT and UART module clock divider as
     * 1 */
    CLK_SetModuleClock(UART2_MODULE, CLK_CLKSEL2_UART2SEL_HXT,
                       CLK_CLKDIV0_UART1(1));

    /* Enable TIMER2 module clock */
    CLK_EnableModuleClock(TMR2_MODULE);
    CLK_SetModuleClock(TMR2_MODULE, CLK_CLKSEL1_TMR2SEL_LIRC, 0);

    /*---------------------------------------------------------------------------------------------------------*/
    /* Init I/O Multi-function */
    /*---------------------------------------------------------------------------------------------------------*/
    /* Set multi-function pins for UART0 RXD and TXD */
    SYS->GPA_MFPL =
        (SYS->GPA_MFPL & (~(UART0_RXD_PA6_Msk | UART0_TXD_PA7_Msk))) |
        UART0_RXD_PA6 | UART0_TXD_PA7;

    /* Set PB multi-function pins for UART1 RXD(PB.6), TXD(PB.7), nRTS(PB.8) and
     * nCTS(PB.9) */
    SYS->GPB_MFPL = (SYS->GPB_MFPL & (~SYS_GPB_MFPL_PB6MFP_Msk)) |
                    SYS_GPB_MFPL_PB6MFP_UART1_RXD;
    SYS->GPB_MFPL = (SYS->GPB_MFPL & (~SYS_GPB_MFPL_PB7MFP_Msk)) |
                    SYS_GPB_MFPL_PB7MFP_UART1_TXD;
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~SYS_GPB_MFPH_PB8MFP_Msk)) |
                    SYS_GPB_MFPH_PB8MFP_UART1_nRTS;
    SYS->GPB_MFPH = (SYS->GPB_MFPH & (~SYS_GPB_MFPH_PB9MFP_Msk)) |
                    SYS_GPB_MFPH_PB9MFP_UART1_nCTS;

    /* Set PC multi-function pins for UART2 RXD(PC.0), TXD(PC.1), nRTS(PC.3) and
     * nCTS(PC.2) */
    SYS->GPC_MFPL = (SYS->GPC_MFPL & (~SYS_GPC_MFPL_PC0MFP_Msk)) |
                    SYS_GPC_MFPL_PC0MFP_UART2_RXD;
    SYS->GPC_MFPL = (SYS->GPC_MFPL & (~SYS_GPC_MFPL_PC1MFP_Msk)) |
                    SYS_GPC_MFPL_PC1MFP_UART2_TXD;
    SYS->GPC_MFPL = (SYS->GPC_MFPL & (~SYS_GPC_MFPL_PC3MFP_Msk)) |
                    SYS_GPC_MFPL_PC3MFP_UART2_nRTS;
    SYS->GPC_MFPL = (SYS->GPC_MFPL & (~SYS_GPC_MFPL_PC2MFP_Msk)) |
                    SYS_GPC_MFPL_PC2MFP_UART2_nCTS;
}

void DEBUG_PORT_Init(void)
{
    DEBUG_PORT->BAUD =
        UART_BAUD_MODE2 | UART_BAUD_MODE2_DIVIDER(__HIRC, 115200);
    DEBUG_PORT->LINE = UART_WORD_LEN_8 | UART_PARITY_NONE | UART_STOP_BIT_1;
}

// 檢查是否是 Base64 字符
bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

// Byte to Base64 編碼
string base64_encode(const unsigned char *bytes_to_encode,
                     unsigned int in_len)
{
    string encoded_string;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) +
                              ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) +
                              ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                encoded_string += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (int j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] =
            ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] =
            ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int j = 0; (j < i + 1); j++)
            encoded_string += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            encoded_string += '=';
    }

    return encoded_string;
}

// Base64 to Byte 解碼
string base64_decode(const char *encoded_string, unsigned int length)
{
    int in_len = length;
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    string decoded_bytes;

    while (in_len-- && (encoded_string[in_] != '=') &&
           is_base64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] =
                (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) +
                              ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                decoded_bytes += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] =
            (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] =
            ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            decoded_bytes += char_array_3[j];
    }

    return decoded_bytes;
}

void separate_hex(const string &hex_str, char *out1, char *out2)
{
    // two hex strings are separated by '/'
    int i = 0;
    char *base64_out1 = (char *)malloc(70);
    char *base64_out2 = (char *)malloc(70);
    memset(base64_out1, 0, 70);
    memset(base64_out2, 0, 70);
    for (; i < hex_str.size(); i++)
    {
        if (hex_str[i] == '-')
        {
            break;
        }
        base64_out1[i] = hex_str[i];
    }
    base64_out1[i] = '\0';
    i++;
    for (int j = 0; i < hex_str.size(); i++, j++)
    {
        base64_out2[j] = hex_str[i];
    }
    base64_out2[i] = '\0';

    // decode base64
    string tout1 = base64_decode(base64_out1, strlen(base64_out1));
    string tout2 = base64_decode(base64_out2, strlen(base64_out2));
    free(base64_out1);
    free(base64_out2);

    // reverse out1
    // reverse(tout1.begin(), tout1.end());
    // reverse(tout2.begin(), tout2.end());

    // convert to hex
    tout1 = byte_to_hex((unsigned char *)tout1.c_str(), tout1.size());
    tout2 = byte_to_hex((unsigned char *)tout2.c_str(), tout2.size());

    // copy to out1 and out2
    strcpy(out1, tout1.c_str());
    strcpy(out2, tout2.c_str());
}

/* Memory organization of data flash */
#define FMC_TEST_ADDR FMC_DTFSH_BASE + 0x4 * DEVICE_MODE_INDEX
#define PRIVATEKEY_KSID FMC_DTFSH_BASE + 0x4 * PRIVATEKEY_INDEX
#define QX_KSID FMC_DTFSH_BASE + 0x4 * QX_KSID_INDEX
#define QY_KSID FMC_DTFSH_BASE + 0x4 * QY_KSID_INDEX
#define OWNER_KEYQX_ADDR FMC_DTFSH_BASE + 0x4 * OWNER_KEYQX_INDEX
#define OWNER_KEYQY_ADDR FMC_DTFSH_BASE + 0x4 * OWNER_KEYQY_INDEX

/* The index of the memory data */
#define DEVICE_MODE_INDEX 0
#define PRIVATEKEY_INDEX 1
#define QX_KSID_INDEX 2
#define QY_KSID_INDEX 3
#define OWNER_KEYQX_INDEX 4
#define OWNER_KEYQY_INDEX 5

int WriteAndVerifyFlash(uint32_t address, uint32_t data)
{
    printf("[M2354] M2354 FMC Application Example\n");

    // 打開 FMC
    FMC_Open();

    // 擦除指定地址
    int eraseResult = FMC_Erase(address);
    if (eraseResult != 0)
    {
        printf("[M2354] Erase failed with error code: %d\n", eraseResult);
        return -1;
    }

    // 寫入數據
    int writeResult = FMC_Write(address, data);
    if (writeResult != 0)
    {
        printf("[M2354] Write failed with error code: %d\n", writeResult);
        return -2;
    }
    printf("[M2354] Data written: 0x%08X\n", data);

    // 讀取數據進行驗證
    uint32_t readData = FMC_Read(address);
    printf("[M2354] Data read: 0x%08X\n", readData);

    if (data == readData)
    {
        printf("[M2354] FMC Write and Read successful!\n");
        return 0; // 成功
    }
    else
    {
        printf("[M2354] FMC Write and Read failed!\n");
        return -3; // 驗證失敗
    }
}
void storeStringToFlash(uint32_t startAddress, const char *str)
{
    int len = strlen(str);
    int numWords = (len + 3) / 4; // 向上取整到最接近的 4 的倍數

    for (int i = 0; i < numWords; i++)
    {
        uint32_t word = 0;
        for (int j = 0; j < 4; j++)
        {
            int index = i * 4 + j;
            if (index < len)
            {
                word |= (uint32_t)str[index] << (j * 8);
            }
            else
            {
                word |= 0x00 << (j * 8); // 填充未使用的字節
            }
        }

        if (WriteAndVerifyFlash(startAddress + i * 4, word) != 0)
        {
            printf("[M2354](storeStringToFlash) Failed to write word at address 0x%08X\n", startAddress + i * 4);
            return;
        }
    }

    printf("[M2354](storeStringToFlash) Successfully wrote string to Flash\n");
}

/*---------------------------------------------------------------------------------------------------------*/
/*  Main Function */

void DeviceController::self_generate_xxx_r_ticket(RTicket &received_r_ticket)
{
    printf("[M2354] info: %s is generating r_ticket\n", shared_data->this_device.device_name.c_str());
    // RTicketGenerator r_ticket_generator =
    //     RTicketGenerator(shared_data->this_device, shared_data->this_person,
    //                      shared_data->device_table);

    // json generated_r_ticket1;
    // generated_r_ticket1.addValueString("device_id", "no_id");
    // generated_r_ticket1.addValueString("protocol_version", "UREKA-1.0");

    received_r_ticket = generate_arbitrary_r_ticket(received_r_ticket);

    // generated_r_ticket.r_ticket_type = "INIT";

    return;
}

RTicket
DeviceController::generate_arbitrary_r_ticket(RTicket received_r_ticket)
{
    string success_msg = "-> SUCCESS: GENERATE_RITICKET";
    string failure_msg = "-> FAILURE: GENERATE_RITICKET";
    /*####################################################
    # Unsigned RTicket
    ####################################################*/

    // TODO, something RTicket(**arbitrary_dict) was written

    // "device"
    if (received_r_ticket.r_ticket_type ==
            u_ticket::TYPE_INITIALIZATION_UTICKET ||
        received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN ||
        received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        received_r_ticket.ticket_order = shared_data->this_device.ticket_order;
    }
    // else if (received_r_ticket.r_ticket_type ==
    //            r_ticket::TYPE_CRKE2_RTICKET) {
    //     received_r_ticket.ticket_order =
    //         shared_data->device_table[received_r_ticket.device_id].ticket_order;
    // }
    else
    {
        printf("[M2354](generate_arbitrary_r_ticket) Error: Unkown RTicket type\n");
        exit(1);
    }
    // TODO: hash received_r_ticket

    char msg[32];
    string r_ticket_str = received_r_ticket.to_json_str();
    my_sha256((char *)r_ticket_str.c_str(), (uint32_t *)msg);
    received_r_ticket.r_ticket_id = base64_encode((unsigned char *)msg, 32);

    // /*####################################################
    // # Signed RTicket
    // ######################################################
    // # Generate Signature

    // # "device"*/

    if (received_r_ticket.r_ticket_type ==
            u_ticket::TYPE_INITIALIZATION_UTICKET ||
        received_r_ticket.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET ||
        received_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN ||
        received_r_ticket.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        self_add_device_signature_on_r_ticket(
            received_r_ticket, shared_data->this_device.device_priv_key,
            r_ticket_str);
        //  log ("info", success_msg);
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else if (received_r_ticket.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        // log ("error", failure_msg);
        printf("[M2354](generate_arbitrary_r_ticket) error: %s\n", failure_msg.c_str());
        exit(1);
    }

    return received_r_ticket;
}

void DeviceController::self_add_device_signature_on_r_ticket(
    RTicket &unsigned_r_ticket, const string &device_priv_key,
    const string &r_ticket_str)
{

    // TODO: sign the r_ticket

    char *r = (char *)malloc(70);
    char *s = (char *)malloc(70);
    memset(r, 0, 70);
    memset(s, 0, 70);

    char ticket_hash[32];
    my_sha256((char *)r_ticket_str.c_str(), (uint32_t *)ticket_hash);

    string ticket_hash_str = byte_to_hex((unsigned char *)ticket_hash, 32);

    if (sign_message(ticket_hash_str.c_str(), (char *)device_priv_key.c_str(),
                     r, s) < 0)
    {
        printf("[M2354](self_add_device_signature_on_r_ticket) Error in signing r ticket\n");
        exit(1);
    }

    string r_byte = hex_to_byte(string(r));
    string s_byte = hex_to_byte(string(s));

    free(r);
    free(s);

    // Add Signature
    // unsigned_r_ticket.device_signature = r_str + "-" + s_str;

    r_byte = base64_encode((unsigned char *)r_byte.c_str(), 32);
    s_byte = base64_encode((unsigned char *)s_byte.c_str(), 32);

    unsigned_r_ticket.device_signature = r_byte + "-" + s_byte;

    return;
}

int DeviceController::self_classify_message_is_defined_type(
    char *arbitrary_json, char *result_message)
{
    printf("[M2354] info %s is classifying message...\n", shared_data->this_device.device_name.c_str());

    // MessageVerifier message_verifier(shared_data->this_device);
    // Message message_in;
    // msg_verify_json_schema(arbitrary_json);
    msg_verify_message_operation(arbitrary_json);
    int message_type = msg_verify_message_type(arbitrary_json);
    if (message_type == -1)
        return -1;
    msg_verify_message_str(arbitrary_json, result_message);

    // result_message = (char *)message_in.message_str.c_str();
    // copy message_in.message_str to result_message

    // strcpy(result_message, message_in.message_str.c_str());

    if (message_type == 1)
    {
        // return make_pair(
        //     self_classify_u_ticket_is_defined_type(message_in.message_str),
        //     RTicket());
        return 1;
    }
    else if (message_type == 2)
    {
        // return make_pair(UTicket(), self_classify_r_ticket_is_defined_type(
        //                                 message_in.message_str));
        return 2;
    }
    else
    {
        printf("-> FAILURE: CLASSIFY_MESSAGE_IS_DEFINED_TYPE\n");
        throw std::runtime_error(
            "-> FAILURE: CLASSIFY_MESSAGE_IS_DEFINED_TYPE");
    }
    return 0;
}

void DeviceController::self_classify_u_ticket_is_defined_type(
    UTicket &received_u_ticket)
{
    printf("[M2354] info %s is classifying u_ticket...\n", shared_data->this_device.device_name.c_str());

    // ThisDevice this_device;
    // UTicketVerifier u_ticket_verifier(this_device);

    // cout << "info: " << arbitrary_json << "\n";
    // printf("info: %s\n", arbitrary_json.c_str());

    u_ticket_verify_protocol_version(received_u_ticket);
    u_ticket_verify_u_ticket_id(received_u_ticket);
    u_ticket_verify_u_ticket_type(received_u_ticket);
    u_ticket_has_device_id(received_u_ticket);

    return;
}

void DeviceController::self_classify_r_ticket_is_defined_type(
    RTicket &received_r_ticket)
{
    printf("[M2354] info %s is classifying r_ticket...\n", shared_data->this_device.device_name.c_str());

    // RTicketVerifier r_ticket_verifier(shared_data->this_device);

    r_ticket_verify_protocol_version(received_r_ticket);
    r_ticket_verify_r_ticket_id(received_r_ticket);
    r_ticket_verify_r_ticket_type(received_r_ticket);
    r_ticket_has_device_id(received_r_ticket);

    return;
}

void DeviceController::verify_u_ticket_can_execute(UTicket u_ticket_in)
{
    // cout << "show me your ass: " << u_ticket_in.to_json_str();
    printf("[M2354] info %s is verifying u_ticket can execute\n", shared_data->this_device.device_name.c_str());

    // UTicketVerifier u_ticket_verifier(shared_data->this_device);

    u_ticket_verify_device_id(u_ticket_in);
    u_ticket_verify_ticket_order(u_ticket_in);
    u_ticket_verify_holder_id(u_ticket_in);
    u_ticket_verify_task_scope(u_ticket_in);
    u_ticket_verify_ps(u_ticket_in);
    u_ticket_verify_issuer_signature(u_ticket_in);

    return;
}

void DeviceController::verify_u_ticket_has_executed_through_r_ticket(
    RTicket &r_ticket_in, UTicket &audit_start_ticket,
    UTicket &audit_end_ticket)
{
    printf("[M2354] info %s is verifying u_ticket has exectued through r_ticket\n", shared_data->this_device.device_name.c_str());

    // RTicketVerifier r_ticket_verifier(
    //     shared_data->this_device, audit_start_ticket, audit_end_ticket,
    //     shared_data->device_table, shared_data->current_session);

    r_ticket_verify_device_id(r_ticket_in, audit_start_ticket);

    // cout << "debug: " << "r_ticket_in result: " << r_ticket_in.result <<
    // "\n";
    r_ticket_verify_result(r_ticket_in);
    r_ticket_verify_ticket_order(r_ticket_in);
    r_ticket_verify_audit_start(r_ticket_in, audit_start_ticket);
    r_ticket_verify_audit_end(r_ticket_in);
    r_ticket_verify_cr_key(r_ticket_in);
    r_ticket_verify_ps(r_ticket_in);
    r_ticket_verify_device_signature(r_ticket_in);
    return;
}

void DeviceController::verify_cmd_is_in_task_scope(const string &cmd)
{
    string success_msg = "-> SUCCESS: VERIFY_CMD_IN_TASK_SCOPE";
    string failure_msg = "-> FAILURE: VERIFY_CMD_IN_TASK_SCOPE";

    json task_scope;
    task_scope.parse(shared_data->current_session.current_task_scope);

    int idx = task_scope.find("ALL");
    int idx2 = task_scope.find("SAY-HELLO-1");
    int idx3 = task_scope.find("SAY-HELLO-2");
    int idx4 = task_scope.find("SAY-HELLO-3");

    if (idx != -1 && task_scope.get_string(idx) == "allow")
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-1" && idx2 != -1 &&
             (task_scope.get_string(idx2) == "allow"))
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-2" && idx3 != -1 &&
             (task_scope.get_string(idx3) == "allow"))
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else if (cmd == "HELLO-3" && idx4 != -1 &&
             (task_scope.get_string(idx4) == "allow"))
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        printf("[M2354] error: %s\n", failure_msg.c_str());
        throw std::runtime_error(failure_msg);
    }

    return;
}

UTicket
DeviceController::u_ticket_verify_json_schema(const char *arbitrary_json)
{
    string arbitrary_json_str;
    // printf("行行好吧 %s\n", arbitrary_json);
    for (int i = 0; i < strlen(arbitrary_json); i++)
    {
        // printf("%c", arbitrary_json[i]);
        arbitrary_json_str += arbitrary_json[i];
    }
    // printf("\n");

    // printf("[M2354] info: input json: %s\n", arbitrary_json_str.c_str());

    UTicket u_ticket_in;
    try
    {
        uticket_from_json_str(arbitrary_json_str, u_ticket_in);
        printf("[M2354] info: -> SUCCESS: VERIFY_JSON_SCHEMA\n");
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(e.what());
    }
    return u_ticket_in;
}

void DeviceController::u_ticket_verify_protocol_version(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PROTOCOL_VERSION";
    string fail_msg = "-> FAILURE: VERIFY_PROTOCOL_VERSION";

    if (u_ticket_in.protocol_version == u_ticket::PROTOCOL_VERSION)
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_u_ticket_id(UTicket &u_ticket_in)
{

    string tmp_id = u_ticket_in.u_ticket_id;
    string tmp_sig = u_ticket_in.issuer_signature;
    // printf("tmp_id: %s\n", tmp_id.c_str());

    u_ticket_in.u_ticket_id = "";
    u_ticket_in.issuer_signature = "";

    // TODO1: hash and check

    unsigned char hash[32];

    my_sha256((char *)u_ticket_in.to_json_str().c_str(), (uint32_t *)hash);

    // byte to base64
    string hash_str = base64_encode(hash, 32);

    u_ticket_in.u_ticket_id = tmp_id;
    u_ticket_in.issuer_signature = tmp_sig;

    // printf("hash: %s\n", hash_str.c_str());
    // printf("tmp_id: %s\n", tmp_id.c_str());

    if (hash_str == tmp_id)
    {
        printf("-> SUCCESS: VERIFY_U_TICKET_ID\n");
    }
    else
    {
        printf("-> FAILURE: VERIFY_U_TICKET_ID\n");
        throw std::runtime_error("-> FAILURE: VERIFY_U_TICKET_ID");
    }
    return;
}

void DeviceController::u_ticket_verify_u_ticket_type(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_U_TICKET_TYPE";
    string fail_msg = "-> FAILURE: VERIFY_U_TICKET_TYPE";

    if (u_ticket::LEGAL_UTICKET_TYPES.find(u_ticket_in.u_ticket_type) !=
        u_ticket::LEGAL_UTICKET_TYPES.end())
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_has_device_id(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: HAS_DEVICE_ID";
    string fail_msg = "-> FAILURE: HAS_DEVICE_ID";

    if (u_ticket_in.device_id != "")
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_device_id(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_ID";
    string fail_msg = "-> FAILURE: VERIFY_DEVICE_ID";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (u_ticket_in.device_id == "no_id")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (u_ticket_in.device_id == shared_data->this_device.device_pub_key)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_ticket_order(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TICKET_ORDER";
    string fail_msg = "-> FAILURE: VERIFY_TICKET_ORDER";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (shared_data->this_device.ticket_order == 0)
        {
            if (u_ticket_in.ticket_order == 0)
            {
                printf("%s\n", success_msg.c_str());
            }
            else
            {
                throw std::runtime_error(fail_msg);
            }
        }
        else if (shared_data->this_device.ticket_order > 0)
        {
            printf("-> FAILURE: VERIFY_TICKET_ORDER: IOT_DEVICE ALREADY INITIALIZED\n");
            throw std::runtime_error("-> FAILURE: VERIFY_TICKET_ORDER: "
                                     "IOT_DEVICE ALREADY INITIALIZED");
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        if (shared_data->this_device.ticket_order == u_ticket_in.ticket_order)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    return;
}

void DeviceController::u_ticket_verify_holder_id(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_HOLDER_ID";
    string fail_msg = "-> FAILURE: VERIFY_HOLDER_ID";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
    {
        if (u_ticket_in.holder_id != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        if (u_ticket_in.holder_id == shared_data->this_device.owner_pub_key)
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_task_scope(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TASK_SCOPE";
    string fail_msg = "-> FAILURE: VERIFY_TASK_SCOPE";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET)
    {
        if (u_ticket_in.task_scope != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        if (u_ticket_in.task_scope == "{\"ALL\": \"allow\"}")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_ps(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PS";
    string fail_msg = "-> FAILURE: VERIFY_PS";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (u_ticket_in.associated_plaintext_cmd != "" &&
            u_ticket_in.ciphertext_cmd != "" && u_ticket_in.iv_data != "" &&
            u_ticket_in.gcm_authentication_tag_cmd != "")
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
    return;
}

void DeviceController::u_ticket_verify_issuer_signature(UTicket &u_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_ISSUER_SIGNATURE";
    string fail_msg = "-> FAILURE: VERIFY_ISSUER_SIGNATURE";

    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
        u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        printf("%s\n", success_msg.c_str());
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        if (self_verify_issuer_signature_on_u_ticket(
                u_ticket_in, shared_data->this_device.owner_pub_key))
        {
            printf("%s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(fail_msg);
            ;
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
        ;
    }
    return;
}

bool DeviceController::self_verify_issuer_signature_on_u_ticket(
    UTicket &signed_u_ticket, const string &public_key)
{
    string success_msg = "-> SUCCESS: SELF_VERIFY_ISSUER_SIGNATURE_ON_U_TICKET";
    string fail_msg = "-> FAILURE: SELF_VERIFY_ISSUER_SIGNATURE_ON_U_TICKET";

    // TODO: verify signature

    string issuer_signature = signed_u_ticket.issuer_signature;
    char *Qx = (char *)malloc(65);
    char *Qy = (char *)malloc(65);
    char *R = (char *)malloc(65);
    char *S = (char *)malloc(65);
    memset(Qx, 0, 65);
    memset(Qy, 0, 65);
    memset(R, 0, 65);
    memset(S, 0, 65);
    separate_hex(issuer_signature, R, S);
    printf("r: %s\n", R);
    printf("s: %s\n", S);
    separate_hex(public_key, Qx, Qy);
    signed_u_ticket.issuer_signature = "";

    unsigned char msg_hash[32];

    // printf("驗證的票長怎樣: %s\n", signed_u_ticket.to_json_str().c_str());

    my_sha256((char *)signed_u_ticket.to_json_str().c_str(),
              (uint32_t *)msg_hash);

    // printf("驗證的hash: %s\n", byte_to_hex(msg_hash, 32).c_str());

    string msg_hash_str = byte_to_hex(msg_hash, 32);

    int ret = verify_signature(Qx, Qy, R, S, msg_hash_str.c_str());

    free(Qx);
    free(Qy);
    free(R);
    free(S);

    if (ret < 0)
    {
        printf("%s\n", fail_msg.c_str());
        throw std::runtime_error(fail_msg);
    }
    else
    {
        printf("%s\n", success_msg.c_str());
        return true;
    }

    return false;
}

RTicket
DeviceController::r_ticket_verify_json_schema(const string &arbitrary_json)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string failure_msg = "-> FAILURE: VERIFY_JSON_SCHEMA";
    // Verify JSON Schema
    RTicket r_ticket_in;
    try
    {
        rticket_from_json_str(arbitrary_json, r_ticket_in);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(failure_msg + " : " + e.what());
    }
    return r_ticket_in;
}

void DeviceController::r_ticket_verify_protocol_version(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PROTOCOL_VERSION";
    string failure_msg = "-> FAILURE: VERIFY_PROTOCOL_VERSION";
    // Verify Protocol Version
    if (r_ticket_in.protocol_version == u_ticket::PROTOCOL_VERSION)
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_r_ticket_id(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_R_TICKET_ID";
    string failure_msg = "-> FAILURE: VERIFY_R_TICKET_ID";
    // Verify R-Ticket ID (Hash-based)
    string id_str = r_ticket_in.r_ticket_id;
    string signature_str = r_ticket_in.device_signature;

    r_ticket_in.r_ticket_id = "";
    r_ticket_in.device_signature = "";

    unsigned char hash[32];
    string message = r_ticket_in.to_json_str();

    my_sha256((char *)message.c_str(), (uint32_t *)hash);

    message = base64_encode(hash, 32);

    if (message == id_str)
    {
        // printf("info: my hash: %s\n", message.c_str());
        // printf("info: %s\n", id_str.c_str());
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        printf("[M2354] info: %s\n", failure_msg.c_str());
        throw std::runtime_error(failure_msg);
    }

    r_ticket_in.r_ticket_id = id_str;
    r_ticket_in.device_signature = signature_str;

    // TODO: hash and check

    return;
}

void DeviceController::r_ticket_verify_r_ticket_type(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_R_TICKET_TYPE";
    string failure_msg = "-> FAILURE: VERIFY_R_TICKET_TYPE";
    // Verify R-Ticket Type

    if (r_ticket::LEGAL_RTICKET_TYPES.find(r_ticket_in.r_ticket_type) !=
        r_ticket::LEGAL_RTICKET_TYPES.end())
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_has_device_id(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: HAS_DEVICE_ID";
    string failure_msg = "-> FAILURE: HAS_DEVICE_ID";
    // Check if R-Ticket has Device ID
    if (r_ticket_in.device_id != "")
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_device_id(RTicket &r_ticket_in,
                                                 UTicket &audit_start_ticket)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_ID";
    string failure_msg = "-> FAILURE: VERIFY_DEVICE_ID";
    // Verify Device ID
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        // u_ticket_device_id = "no_id"
        // r_ticket_device_id = "newly_created_device public key string"

        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else if (r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
             r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN ||
             r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.device_id == audit_start_ticket.device_id)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket::LEGAL_CRKE_TYPES.find(r_ticket_in.r_ticket_type) !=
             r_ticket::LEGAL_CRKE_TYPES.end())
    {
        if (r_ticket_in.device_id ==
            shared_data->current_session.current_device_id)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_result(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_RESULT";
    string failure_msg = "-> FAILURE: VERIFY_RESULT";
    // Verify Result
    if (r_ticket_in.result.find("SUCCESS") != string::npos)
    {
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

// verify_ticket_order
void DeviceController::r_ticket_verify_ticket_order(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_TICKET_ORDER";
    string failure_msg = "-> FAILURE: VERIFY_TICKET_ORDER";
    // Verify Ticket Order
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        if (r_ticket_in.ticket_order == 1)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.ticket_order == shared_data->this_device.ticket_order)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else
    {

        throw std::runtime_error(failure_msg);
    }
    return;
}

// verify_audi_start

void DeviceController::r_ticket_verify_audit_start(
    RTicket &r_ticket_in, UTicket &audit_start_ticket)
{
    string success_msg = "-> SUCCESS: VERIFY_AUDIT_START";
    string failure_msg = "-> FAILURE: VERIFY_AUDIT_START";
    // Verify Audit Start
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.audit_start == audit_start_ticket.u_ticket_id)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket::LEGAL_CRKE_TYPES.find(r_ticket_in.r_ticket_type) !=
             r_ticket::LEGAL_CRKE_TYPES.end())
    {
        if (r_ticket_in.audit_start ==
            shared_data->current_session.current_u_ticket_id)
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_audit_end(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_AUDIT_END";
    string failure_msg = "-> FAILURE: VERIFY_AUDIT_END";
    // Verify Audit End
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (r_ticket_in.audit_end == "ACCESS_END")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    return;
}

void DeviceController::r_ticket_verify_cr_key(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_CR_KEY";
    string failure_msg = "-> FAILURE: VERIFY_CR_KEY";
    // Verify CR Key
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {
        if (r_ticket_in.challenge_1 != "" &&
            r_ticket_in.key_exchange_salt_1 != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.challenge_2 != "" && r_ticket_in.challenge_1 != "" &&
            r_ticket_in.key_exchange_salt_2 != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        if (r_ticket_in.challenge_2 != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_ps(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_PS";
    string failure_msg = "-> FAILURE: VERIFY_PS";
    // Verify PS
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
        r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE1_RTICKET)
    {
        if (r_ticket_in.iv_cmd != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        if (r_ticket_in.associated_plaintext_cmd != "" &&
            r_ticket_in.ciphertext_cmd != "" && r_ticket_in.iv_data != "" &&
            r_ticket_in.gcm_authentication_tag_cmd != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE3_RTICKET)
    {
        if (r_ticket_in.associated_plaintext_data != "" &&
            r_ticket_in.ciphertext_data != "" && r_ticket_in.iv_cmd != "" &&
            r_ticket_in.gcm_authentication_tag_data != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        if (r_ticket_in.associated_plaintext_data != "" &&
            r_ticket_in.ciphertext_data != "" && r_ticket_in.iv_cmd != "" &&
            r_ticket_in.gcm_authentication_tag_data != "")
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

void DeviceController::r_ticket_verify_device_signature(RTicket &r_ticket_in)
{
    string success_msg = "-> SUCCESS: VERIFY_DEVICE_SIGNATURE";
    string failure_msg = "-> FAILURE: VERIFY_DEVICE_SIGNATURE";
    // Verify Device Signature
    if (r_ticket_in.r_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {

        // TODO : something should be checked
        if (self_verify_device_signature_on_r_ticket(r_ticket_in,
                                                     r_ticket_in.device_id))
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {

        if (self_verify_device_signature_on_r_ticket(
                r_ticket_in, shared_data->current_session.current_holder_id))
        {
            printf("[M2354] info: %s\n", success_msg.c_str());
        }
        else
        {
            throw std::runtime_error(failure_msg);
        }
    }
    else if (r_ticket_in.r_ticket_type == r_ticket::TYPE_DATA_RTOKEN)
    {
        // no device_signature
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    else
    {
        throw std::runtime_error(failure_msg);
    }
    return;
}

bool DeviceController::self_verify_device_signature_on_r_ticket(
    RTicket &signed_r_ticket, const string &public_key)
{
    string success_msg = "-> SUCCESS: SELF_VERIFY_DEVICE_SIGNATURE_ON_R_TICKET";
    string failure_msg = "-> FAILURE: SELF_VERIFY_DEVICE_SIGNATURE_ON_R_TICKET";
    // Verify ECC Signature on RTicket

    string signature_tmp = signed_r_ticket.device_signature;
    signed_r_ticket.device_signature = "";
    char *Qx = (char *)malloc(65);
    char *Qy = (char *)malloc(65);
    char *R = (char *)malloc(65);
    char *S = (char *)malloc(65);
    memset(Qx, 0, 65);
    memset(Qy, 0, 65);
    memset(R, 0, 65);
    memset(S, 0, 65);
    separate_hex(signature_tmp, R, S);
    separate_hex(public_key, Qx, Qy);

    unsigned char msg_hash[32];

    my_sha256((char *)signed_r_ticket.to_json_str().c_str(),
              (uint32_t *)msg_hash);

    string msg_hash_str = byte_to_hex(msg_hash, 32);

    int ret = verify_signature(Qx, Qy, R, S, msg_hash_str.c_str());

    free(Qx);
    free(Qy);
    free(R);
    free(S);

    if (ret < 0)
    {
        printf("[M2354] info: %s\n", failure_msg.c_str());
        throw std::runtime_error(failure_msg);
    }
    else
    {
        printf("[M2354] info: %s\n", success_msg.c_str());

        return true;
    }

    return true;
}

void DeviceController::msg_verify_json_schema(const string &arbitrary_json,
                                              Message &message_in)
{
    string success_msg = "-> SUCCESS: VERIFY_JSON_SCHEMA";
    string fail_msg = "-> FAIL: VERIFY_JSON_SCHEMA";

    try
    {
        message_from_json_str(arbitrary_json, message_in);
        printf("[M2354] info: %s\n", success_msg.c_str());
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error(fail_msg + " : " + e.what());
    }

    return;
}

void DeviceController::msg_verify_message_operation(
    const char *arbitrary_json)
{
    const char *success_msg = "-> SUCCESS: VERIFY_MESSAGE_OPERATION";
    const char *fail_msg = "-> FAIL: VERIFY_MESSAGE_OPERATION";

    const char *start_str = "\"message_operation\":\"";
    const char *end_str = "\",\"message_type\":\"";

    const char *start_ptr = strstr(arbitrary_json, start_str);
    if (!start_ptr)
    {
        throw std::runtime_error(fail_msg);
    }
    start_ptr += strlen(start_str); // 移動到 "message_operation" 的值部分

    const char *end_ptr = strstr(start_ptr, end_str);
    if (!end_ptr)
    {
        throw std::runtime_error(fail_msg);
    }

    size_t message_operation_len = end_ptr - start_ptr;
    std::string message_operation(start_ptr, message_operation_len);

    if (message_operation == message::MESSAGE_RECV_AND_STORE ||
        message_operation == message::MESSAGE_VERIFY_AND_EXECUTE ||
        message_operation == "PERMISSIONLESS")
    {
        printf("[M2354] info: %s\n", success_msg);
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
}

int DeviceController::msg_verify_message_type(const char *arbitrary_json)
{
    const char *success_msg = "-> SUCCESS: VERIFY_MESSAGE_TYPE";
    const char *fail_msg = "-> FAIL: VERIFY_MESSAGE_TYPE";

    const char *start_str = "\"message_type\":\"";
    const char *end_str = "\",\"message_str\":\"";

    const char *start_ptr = strstr(arbitrary_json, start_str);
    if (!start_ptr)
    {
        throw std::runtime_error(fail_msg);
    }
    start_ptr += strlen(start_str);

    const char *end_ptr = strstr(start_ptr, end_str);
    if (!end_ptr)
    {
        throw std::runtime_error(fail_msg);
    }

    std::string message_type(start_ptr, end_ptr - start_ptr);

    if (message_type == "UTICKET")
    {
        printf("[M2354] info: %s UTICKET\n", success_msg);
        return 1;
    }
    else if (message_type == "RTICKET")
    {
        printf("[M2354] info: %s RTICKET\n", success_msg);
        return 2;
    }
    else if (message_type == "PERMISSIONLESS")
    {
        return -1;
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }

    return 0;
}

void DeviceController::msg_verify_message_str(const char *arbitrary_json,
                                              char *msg)
{
    const char *success_msg = "-> SUCCESS: VERIFY_MESSAGE_STR";
    const char *fail_msg = "-> FAIL: VERIFY_MESSAGE_STR";

    const char *start_str = "\"message_str\":\"";
    const char *end_str = "}\"}";

    const char *start_ptr = strstr(arbitrary_json, start_str);
    if (!start_ptr)
    {
        throw std::runtime_error(fail_msg);
    }
    start_ptr += strlen(start_str);

    const char *end_ptr = strstr(start_ptr, end_str);
    if (!end_ptr)
    {
        throw std::runtime_error(fail_msg);
    }

    size_t length = end_ptr - start_ptr;
    if (length >= 1)
    {
        strncpy(msg, start_ptr, length);
        msg[length] = '}';
        msg[length + 1] = '\0';

        remove_something(msg);

        if (strlen(msg) > 0)
        {
            printf("[M2354] info: %s\n", success_msg);
        }
        else
        {
            throw std::runtime_error(fail_msg);
        }
    }
    else
    {
        throw std::runtime_error(fail_msg);
    }
}

void DeviceController::self_change_state(const string &new_state)
{
    shared_data->state = new_state;
}

bool DeviceController::self_initialize_state()
{
    if (shared_data->this_device.device_type == this_device::IOT_DEVICE)
    {
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        return true;
    }
    else if (shared_data->this_device.device_type ==
             this_device::USER_AGENT_OR_CLOUD_SERVER)
    {
        self_change_state(this_device::STATE_AGENT_WAIT_FOR_UREQ_UREJ_UT_RT);
        return true;
    }

    return false;
}

bool DeviceController::self_execute_one_time_set_time_device_type_and_name(
    const string &device_type, const string &device_name)
{
    /*####################################################
    # Determine device type name, but still be uninitialized
    # Determine device name (for test)
    ####################################################*/
    shared_data->this_device.device_type = device_type;
    shared_data->this_device.device_name = device_name;
    shared_data->this_device.has_device_type = true;

    /*####################################################
    # Initial Order
    ####################################################*/

    // [STAGE: (O)]
    UTicket u_ticket;
    RTicket r_ticket;
    self_execute_update_ticket_order("has-type", 0, u_ticket, r_ticket);

    /*####################################################
    # Storage
    ####################################################*/

    // TODO
    return true;
}

void DeviceController::self_execute_xxx_u_ticket(UTicket u_ticket_in)
{

    RTicket no_use_r_ticket;
    if (u_ticket_in.u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_one_time_initialize_iot_device(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1,
                                         u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_ownership_transfer(u_ticket_in);

        // [STAGE: (O)]
        self_execute_update_ticket_order("device-verify-uticket", 1,
                                         u_ticket_in, no_use_r_ticket);
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET)
    {
        // [STAGE: (E)]
        self_execute_cr_ke(1, u_ticket_in, no_use_r_ticket, "device");
    }
    else if (u_ticket_in.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        self_execute_ps("recv-utoken", 1, u_ticket_in, no_use_r_ticket, "", "");

        string plaintext_data = shared_data->current_session.plaintext_cmd;
        string associated_plaintext_data =
            shared_data->current_session.associated_plaintext_cmd;
        self_execute_data_processing(plaintext_data, associated_plaintext_data);
        // Update Session: PS-Data
        self_execute_ps("send-rtoken", 1, u_ticket_in, no_use_r_ticket,
                        plaintext_data, associated_plaintext_data);

        if (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (VTK)]
            if (shared_data->current_session.plaintext_cmd == "ACCESS_END_C" ||
                shared_data->current_session.plaintext_cmd == "ACCESS_END_T" ||
                shared_data->current_session.plaintext_cmd == "ACCESS_END")
            {
                shared_data->result_message = "-> SUCCESS: VERIFY_ACCESS_END";

                // [STAGE: (O)]
                self_execute_update_ticket_order("device-verify-uticket", 1,
                                                 u_ticket_in, no_use_r_ticket);
            }
            else
            {
                shared_data->result_message = "-> FAILURE: VERIFY_ACCESS_END";
                printf("-> FAILURE: VERIFY_ACCESS_END\n");
            }
        }
    }
}

void DeviceController::self_execute_xxx_r_ticket(RTicket r_ticket_in,
                                                 const string &comm_end)
{
    UTicket no_use_u_ticket;
    if (comm_end == "holder-or-device")
    {
        if (r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
        {
            // [STAGE: (E)]
            self_execute_cr_ke(2, no_use_u_ticket, r_ticket_in, "device");
        }
        else
        {
            printf("should not be here (self_execute_xxx_r_ticket)\n");
        }
    }
}

void DeviceController::self_execute_one_time_initialize_iot_device(
    UTicket u_ticket_in)
{
    char output[66];

    printf("[M2354] info: %s is initializing...\n", shared_data->this_device.device_name.c_str());

    if (shared_data->this_device.device_type != this_device::IOT_DEVICE)
    {
        // FAILURE: (VRESET)
        printf("-> FAILURE: ONLY IOT_DEVICE CAN DO THIS INITIALIZATION OPERATION\n");
        return;
    }

    /*####################################################
    # Initialize Device Id
    ####################################################*/

    // TODO: generate key pair and store

    char *d, *Qx, *Qy;
    d = (char *)malloc(65);
    Qx = (char *)malloc(65);
    Qy = (char *)malloc(65);
    memset(d, 0, 65);
    memset(Qx, 0, 65);
    memset(Qy, 0, 65);

    if (generate_keys(d, Qx, Qy) < 0)
    {
        printf("-> FAILURE: GENERATE DEVICE KEY PAIR\n");
        throw std::runtime_error("-> FAILURE: GENERATE DEVICE KEY PAIR");
        return;
    }
    shared_data->this_device.device_priv_key = string(d);
    free(d);

    string Qx_byte = hex_to_byte(string(Qx));
    string Qy_byte = hex_to_byte(string(Qy));
    free(Qx);
    free(Qy);

    Qx_byte =
        base64_encode((const unsigned char *)Qx_byte.c_str(), Qx_byte.size());
    Qy_byte =
        base64_encode((const unsigned char *)Qy_byte.c_str(), Qy_byte.size());

    shared_data->this_device.device_pub_key = Qx_byte + "-" + Qy_byte;

    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;
}

void DeviceController::self_execute_ownership_transfer(UTicket u_ticket_in)
{
    printf("[M2354] info: %s is transferring ownership...\n", shared_data->this_device.device_name.c_str());

    shared_data->this_device.owner_pub_key = u_ticket_in.holder_id;
}

void DeviceController::self_execute_cr_ke(int UR, UTicket &u_ticket_in,
                                          RTicket &r_ticket_in,
                                          const string &comm_end,
                                          const string &cmd)
{
    printf("[M2354] info: %s is executing cr_ke...\n", shared_data->this_device.device_name.c_str());

    UTicket no_use_u_ticket;
    RTicket no_use_r_ticket;
    if (UR == 1 &&
        (u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_UTICKET ||
         u_ticket_in.u_ticket_type == u_ticket::TYPE_SELFACCESS_UTICKET))
    {
        // Update session: Access UT
        shared_data->current_session.current_u_ticket_id =
            u_ticket_in.u_ticket_id;
        shared_data->current_session.current_device_id = u_ticket_in.device_id;
        shared_data->current_session.current_holder_id = u_ticket_in.holder_id;
        shared_data->current_session.current_task_scope =
            u_ticket_in.task_scope;

        // Update Session: CR
        shared_data->current_session.challenge_1 = generate_random_str(32);

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_1 =
            generate_random_str(32);

        // Update Session: PS-Cmd
        self_execute_ps("recv-ut-and-send-crke1", 0, no_use_u_ticket,
                        no_use_r_ticket, "", "");
    }
    else if (UR == 2 &&
             r_ticket_in.r_ticket_type == r_ticket::TYPE_CRKE2_RTICKET)
    {
        // Update Session: CR
        shared_data->current_session.challenge_2 = r_ticket_in.challenge_2;

        // Update Session: KE
        shared_data->current_session.key_exchange_salt_2 =
            r_ticket_in.key_exchange_salt_2;
        string current_session_key_byte = self_execute_generate_session_key(
            shared_data->current_session.key_exchange_salt_1,
            shared_data->current_session.key_exchange_salt_2,
            shared_data->this_device.device_priv_key,
            shared_data->current_session.current_holder_id);

        shared_data->current_session.current_session_key_str =
            current_session_key_byte;

        // Update Session: PS-Cmd
        self_execute_ps("recv-crke2", 2, no_use_u_ticket, r_ticket_in, "", "");
        string plaintext_data = shared_data->current_session.plaintext_cmd;
        string associated_plaintext_data =
            shared_data->current_session.associated_plaintext_cmd;

        // self_execute_data_processing(plaintext_data,
        // associated_plaintext_data);

        // Update Session: PS-Data

        self_execute_ps("send-crke3", 2, no_use_u_ticket, r_ticket_in,
                        "DATA: " + plaintext_data,
                        "DATA: " + associated_plaintext_data);
    }
    else
    {
        printf("should not be here (self_execute_cr_ke)\n");
    }
}

string DeviceController::self_execute_generate_session_key(const string &salt_1,
                                                           const string &salt_2,
                                                           string &priv_key,
                                                           string &pub_key)
{
    string shared_salt_bytes;
    for (int i = 0; i < salt_1.size(); i++)
    {
        shared_salt_bytes += salt_1[i] & salt_2[i];
    }

    // string priv_key_hex = base64_decode(priv_key.c_str(), priv_key.size());
    // priv_key_hex = byte_to_hex((unsigned char *)priv_key_hex.c_str(), 32);
    char *pub_key_hex_x = (char *)malloc(65);
    char *pub_key_hex_y = (char *)malloc(65);
    memset(pub_key_hex_x, 0, 65);
    memset(pub_key_hex_y, 0, 65);
    separate_hex(pub_key, pub_key_hex_x, pub_key_hex_y);

    char *k = (char *)malloc(65);
    memset(k, 0, 65);
    int ret = generate_secret_keys((char *)priv_key.c_str(), pub_key_hex_x,
                                   pub_key_hex_y, k);

    free(pub_key_hex_x);
    free(pub_key_hex_y);
    if (ret < 0)
    {
        printf("-> FAILURE: GENERATE SESSION KEY\n");
        throw std::runtime_error("-> FAILURE: GENERATE SESSION KEY");
    }
    // TODO

    string ret_str = string(k);
    free(k);

    return ret_str;
}

// void DeviceController::self_execute_cmd(const string &cmd) {
//     printf("info: %s is executing cmd...\n",shared_data->this_device.device_name.c_str());

// }

void DeviceController::self_execute_ps(const string &executing_case, int UR,
                                       UTicket u_ticket_in, RTicket r_ticket_in,
                                       const string &plaintext,
                                       const string &associated_plaintext)
{
    printf("[M2354] info: %s is executing ps...\n", shared_data->this_device.device_name.c_str());

    if (executing_case == "send-ut")
    {
        // Update Session: PS-Cmd (input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd =
            "additional unencrypted cmd";
    }
    else if (executing_case == "recv-ut-and-send-crke1")
    {
        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "recv-crke2")
    {
        // Update Session: PS-Data
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd =
                u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd =
                u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd =
                u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd =
                r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd =
                r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd =
                r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-cmd (Decryption)
        char decrypted_plaintext[50] = "";
        self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd, decrypted_plaintext);

        verify_cmd_is_in_task_scope(decrypted_plaintext);

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd =
            string(decrypted_plaintext);
    }
    else if (executing_case == "send-crke3")
    {
        // update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            printf("should not be here (self_execute_ps) (send-crke3)\n");
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data =
            associated_plaintext;

        // Update Session: PS-Data(Encryption)
        self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.iv_data);

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else if (executing_case == "send-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_cmd = plaintext;
        shared_data->current_session.associated_plaintext_cmd =
            "additional unencrypted cmd";

        // Update Session: PS-Cmd (Encryption)
        self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.iv_cmd);

        // Update Session: Next-IV
        shared_data->current_session.iv_data = self_gen_next_iv();
    }
    else if (executing_case == "recv-utoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        // Update Session: PS-Cmd (Input: ciphertext, associated_plaintext,
        // gcm_authentication_tag)
        if (UR == 1)
        {
            shared_data->current_session.ciphertext_cmd =
                u_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd =
                u_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd =
                u_ticket_in.gcm_authentication_tag_cmd;
        }
        else if (UR == 2)
        {
            shared_data->current_session.ciphertext_cmd =
                r_ticket_in.ciphertext_cmd;
            shared_data->current_session.associated_plaintext_cmd =
                r_ticket_in.associated_plaintext_cmd;
            shared_data->current_session.gcm_authentication_tag_cmd =
                r_ticket_in.gcm_authentication_tag_cmd;
        }

        // [STAGE: (VTK)(VTS)]
        // Update Session: PS-Cmd (Decryption)
        char decrypted_plaintext[15] = "";
        self_execute_decrypt_ciphertext(
            shared_data->current_session.ciphertext_cmd,
            shared_data->current_session.associated_plaintext_cmd,
            shared_data->current_session.gcm_authentication_tag_cmd,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.iv_cmd, decrypted_plaintext);

        if (UR == 1 &&
            u_ticket_in.u_ticket_type != u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            verify_cmd_is_in_task_scope(string(decrypted_plaintext));
            // self_execute_cmd(string(decrypted_plaintext));
        }
        else
        {
            printf("should not be here (self_execute_ps) (recv-utoken)\n");
        }

        // Update Session: PS-Cmd (Output: plaintext)
        shared_data->current_session.plaintext_cmd = decrypted_plaintext;
    }
    else if (executing_case == "send-rtoken")
    {
        // Update Session: PS-Cmd (Input: This-IV)
        if (UR == 1)
        {
            shared_data->current_session.iv_data = u_ticket_in.iv_data;
        }
        else if (UR == 2)
        {
            shared_data->current_session.iv_data = r_ticket_in.iv_data;
        }

        // Update Session: PS-DATA (Input: plaintext, associated_plaintext)
        shared_data->current_session.plaintext_data = plaintext;
        shared_data->current_session.associated_plaintext_data =
            associated_plaintext;

        // Update Session: PS-Data (Encryption)
        self_execute_encrypt_plaintext(
            shared_data->current_session.plaintext_data,
            shared_data->current_session.associated_plaintext_data,
            shared_data->current_session.current_session_key_str,
            shared_data->current_session.ciphertext_data,
            shared_data->current_session.gcm_authentication_tag_data,
            shared_data->current_session.iv_data);

        // Update Session: Next-IV
        shared_data->current_session.iv_cmd = self_gen_next_iv();
    }
    else
    {
        printf("%s\n", executing_case.c_str());
        throw std::runtime_error("should not be here (self_execute_ps)");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}

void DeviceController::self_execute_encrypt_plaintext(
    const string &plaintext, const string &associated_plaintext,
    const string &session_key, string &ciphertext,
    string &gcm_authentication_tag, const string &iv)
{
    printf("[M2354] info: %s is encrypting plaintext...\n", shared_data->this_device.device_name.c_str());

    char *ciphertext_byte = (char *)malloc(100);
    memset(ciphertext_byte, 0, 100);
    string iv_byte = base64_decode(iv.c_str(), iv.size());
    iv_byte = byte_to_hex((unsigned char *)iv_byte.c_str(), iv_byte.size());

    uint32_t plen_aligned, plen;

    char *decrypted_plaintext = (char *)malloc(100);
    memset(decrypted_plaintext, 0, 100);

    int ret = gcm_encrypt((char *)session_key.c_str(), (char *)iv_byte.c_str(),
                          (char *)associated_plaintext.c_str(),
                          (char *)plaintext.c_str(), (uint8_t *)ciphertext_byte,
                          &plen_aligned, &plen);

    if (ret < 0)
    {
        free(ciphertext_byte);
        free(decrypted_plaintext);
        printf("-> FAILURE: VERIFY_IV_AND_HMAC\n");
        throw std::runtime_error("-> FAILURE: VERIFY_IV_AND_HMAC");
    }
    else
    {
        char *g_C = (char *)malloc(plen_aligned);
        memset(g_C, 0, plen_aligned);
        char g_T[16];
        strncpy(g_C, ciphertext_byte, plen);
        strncpy(g_T, (ciphertext_byte + plen_aligned), 16);
        ciphertext = base64_encode((const unsigned char *)g_C, plen);
        gcm_authentication_tag = base64_encode((const unsigned char *)g_T, 16);
        free(ciphertext_byte);
        free(decrypted_plaintext);
    }

    return;
}

void DeviceController::self_execute_decrypt_ciphertext(
    const string &ciphertext, const string &associated_plaintext,
    const string &gcm_authentication_tag, const string &session_key,
    const string &iv, char *decrypted_plaintext)
{
    printf("[M2354] info: %s is decrypting ciphertext...\n", shared_data->this_device.device_name.c_str());

    try
    {
        string ciphertext_hex =
            base64_decode(ciphertext.c_str(), ciphertext.size());

        uint32_t C_len = ciphertext_hex.size();

        string gcm_authentication_tag_hex = base64_decode(
            gcm_authentication_tag.c_str(), gcm_authentication_tag.size());

        string iv_hex = base64_decode(iv.c_str(), iv.size());

        iv_hex = byte_to_hex((unsigned char *)iv_hex.c_str(), iv_hex.size());
        ciphertext_hex += gcm_authentication_tag_hex;
        string key_byte = hex_to_byte(session_key);

        int ret = gcm_decrypt(
            (char *)session_key.c_str(), (char *)iv_hex.c_str(),
            (char *)associated_plaintext.c_str(),
            (uint8_t *)ciphertext_hex.c_str(), decrypted_plaintext, C_len);

        if (ret < 0)
        {
            printf("-> FAILURE: VERIFY_IV_AND_HMAC\n");
            throw std::runtime_error("-> FAILURE: VERIFY_IV_AND_HMAC");
        }
        else
        {
            printf("[M2354] 解密完畢: %s\n", decrypted_plaintext);
        }

        return;
    }
    catch (const std::exception &e)
    {
        string error_message = e.what();
        shared_data->result_message = "-> FAILURE: VERIFY_IV_AND_HMAC";
        printf("error: %s\n", error_message.c_str());
        throw;
    }
    catch (...)
    {
        throw std::runtime_error(
            "should not be here (self_execute_decrypt_ciphertext)");
    }
}

void DeviceController::self_execute_data_processing(
    string &plaintext_cmd, string &associated_plaintext_cmd)
{
    printf("[M2354] info: %s is executing application...\n", shared_data->this_device.device_name.c_str());
    associated_plaintext_cmd = "DATA: " + associated_plaintext_cmd;

    if (plaintext_cmd.empty())
    {
        printf("-> FAILURE: EMPTY CMD\n");
        throw std::runtime_error("-> FAILURE: EMPTY CMD");
    }
    else if (plaintext_cmd == "ACCESS_END")
    {
        return;
    }

    if (voting_state == VOTING_STATE::BEFORE_VOTING)
    {
        if (plaintext_cmd == "ACCESS_END_C")
        {
            voting_state = VOTING_STATE::DURING_VOTING;
            return;
        }

        if (plaintext_cmd[0] == 'C')
        {
            if (plaintext_cmd[1] == ':')
            {
                // VOTE TODO: store the candidates name
                if (candidate_num < voting_candidates.size())
                {
                    voting_candidates[candidate_num].first =
                        plaintext_cmd.substr(2);
                    voting_candidates[candidate_num].second = 0;
                }
                else
                    voting_candidates.push_back(
                        make_pair(plaintext_cmd.substr(2), 0));

                candidate_num++;
                printf("add candidate: %s\n", plaintext_cmd.substr(2).c_str());
                plaintext_cmd = "CandidateAdded";
            }
            else if (plaintext_cmd[1] == '-')
            {
                // VOTE TODO: store the voter public keys
                if (voter_num < VOTER_SIZE)
                {
                    voting_voters[voter_num].first = plaintext_cmd.substr(2);
                    voting_voters[voter_num].second = false;
                }
                // else
                //     voting_voters.push_back(
                //         make_pair(plaintext_cmd.substr(2), false));

                printf("add voter: %s\n", voting_voters[voter_num].first.c_str());
                voter_num++;
                // printf("add voter: %s\n", plaintext_cmd.substr(2).c_str());
                plaintext_cmd = "VoterAdded";
            }
            else
            {
                candidate_num = 0;
                voter_num = 0;
                // throw std::runtime_error("-> FAILURE: INVALID CMD");
            }
        }
        else
        {
            printf("-> FAILURE: INVALID CMD\n");
            throw std::runtime_error("-> FAILURE: INVALID CMD");
        }
    }
    else if (voting_state == VOTING_STATE::DURING_VOTING)
    {
        if (plaintext_cmd == "ACCESS_END_T")
        {
            voting_state = VOTING_STATE::BEFORE_VOTING;

            return;
        }
        if (plaintext_cmd[0] == 'A' && plaintext_cmd.size() == 1)
        {
            // VOTE TODO: modify plaintext_cmd, should be
            // 0.[name]1.[name]2.[name]...
            plaintext_cmd = "";
            for (int i = 0; i < voting_candidates.size(); i++)
            {
                plaintext_cmd +=
                    to_string(i) + ":" + voting_candidates[i].first + ":";
            }
        }
        else if (plaintext_cmd[0] == 'V' && plaintext_cmd[1] == ':')
        {
            // get the string after 'V:'
            string vote = plaintext_cmd.substr(2);
            int vote_num = stoi(vote);
            // VOTE TODO: store the vote
            // find the voter and set the vote to true
            for (int i = 0; i < voter_num; i++)
            {
                printf("voter: %s, and expected %s\n", voting_voters[i].first.c_str(), shared_data->current_session.current_holder_id.c_str());
                if (voting_voters[i].first ==
                    shared_data->current_session.current_holder_id)
                {
                    if (voting_voters[i].second)
                    {
                        printf("-> FAILURE: VOTER ALREADY VOTED\n");
                        throw std::runtime_error(
                            "-> FAILURE: VOTER ALREADY VOTED");
                    }
                    voting_voters[i].second = true;
                    voting_candidates[vote_num].second += 1;
                    return;
                }
            }
            throw std::runtime_error("-> FAILURE: INVALID VOTER");
        }
        else if (plaintext_cmd[0] == 'T' && plaintext_cmd[1] == 'C')
        {
            // VOTE TODO: modify plaintext_cmd, should be
            // 0.[name, vote]1.[name, vote]2.[name, vote]...
            // plaintext_cmd = "";
            associated_plaintext_cmd = "DATA: ";
            for (int i = 0; i < voting_candidates.size(); i++)
            {
                associated_plaintext_cmd +=
                    to_string(i) + ":" + voting_candidates[i].first + "," +
                    to_string(voting_candidates[i].second) + ":";
            }
        }
        else if (plaintext_cmd[0] == 'T' && plaintext_cmd[1] == 'V')
        {
            // get the string after 'TV'
            string voter = plaintext_cmd.substr(2);
            int voter_index = stoi(voter);
            // VOTE TODO: send the voter info back, if invalid, send "-----"
            if (voter_index < VOTER_SIZE)
            {
                // [public_key]:[vote or not]
                associated_plaintext_cmd =
                    "DATA: " + voter + ":" +
                    (voting_voters[voter_index].second ? "1" : "0");
            }
            else
            {
                associated_plaintext_cmd = "DATA: -----";
            }
        }
        else
        {
            printf("-> FAILURE: INVALID CMD\n");
            throw std::runtime_error("-> FAILURE: INVALID CMD");
        }
    }
    else
    {
        printf("-> FAILURE: INVALID VOTING STATE\n");
        throw std::runtime_error("-> FAILURE: INVALID VOTING STATE");
    }

    // plaintext_cmd = "DATA: " + plaintext_cmd;
    // associated_plaintext_cmd = "DATA: " + associated_plaintext_cmd;
    return;
}

void DeviceController::self_execute_update_ticket_order(
    const string &updating_case, int UR, UTicket u_ticket_in,
    RTicket r_ticket_in)
{
    printf("[M2354] info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());

    if (updating_case == "has-type")
    {
        shared_data->this_device.ticket_order = 0;
    }
    else if (updating_case == "agent-initialization")
    {
        shared_data->this_device.ticket_order += 1;
    }
    else if (updating_case == "device-verify-uticket")
    {
        // Execute UTicket
        if (UR == 1 &&
            (u_ticket_in.u_ticket_type ==
                 u_ticket::TYPE_INITIALIZATION_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET ||
             u_ticket_in.u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN))
        {
            shared_data->this_device.ticket_order += 1;
            printf("[M2354] info: %s is updating ticket order...\n", shared_data->this_device.device_name.c_str());
        }
        else
        {
            printf("should not be here (self_execute_update_ticket_order)\n");
        }
    }
    else
    {
        printf("should not be here (self_execute_update_ticket_order)\n");
    }

    /*############################################
    # Storage
    ############################################*/

    // TODO
}

string DeviceController::self_gen_next_iv()
{
    // string iv = gcm_gen_iv();
    // iv = hex_to_byte(iv);
    // iv = base64_encode((const unsigned char *)iv.c_str(), iv.size());
    return gcm_gen_iv();
}

void print_that_ticket(const RTicket &sent_message)
{
    bool first = true;
    if (sent_message.protocol_version != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"protocol_version\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.protocol_version))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.r_ticket_id != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"r_ticket_id\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.r_ticket_id)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.r_ticket_type != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"r_ticket_type\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.r_ticket_type)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.device_id != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"device_id\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.device_id)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.result != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"result\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.result)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (first)
    {
        first = false;
    }
    else
        BLE_SendMessage(", ");
    BLE_SendMessage("\\\"ticket_order\\\":");
    string ticket_order = to_string(sent_message.ticket_order);
    BLE_SendMessage(ticket_order.c_str());
    if (sent_message.audit_start != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"audit_start\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.audit_start)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.audit_end != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"audit_end\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.audit_end)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.challenge_1 != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"challenge_1\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.challenge_1)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.challenge_2 != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"challenge_2\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.challenge_2)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.key_exchange_salt_1 != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"key_exchange_salt_1\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.key_exchange_salt_1))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.key_exchange_salt_2 != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"key_exchange_salt_2\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.key_exchange_salt_2))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.associated_plaintext_cmd != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"associated_plaintext_cmd\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.associated_plaintext_cmd))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.ciphertext_cmd != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"ciphertext_cmd\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.ciphertext_cmd)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.iv_cmd != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"iv_cmd\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.iv_cmd)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.gcm_authentication_tag_cmd != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"gcm_authentication_tag_cmd\\\":\\\"");
        BLE_SendMessage(
            add_that_json(
                add_that_json(sent_message.gcm_authentication_tag_cmd))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.associated_plaintext_data != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"associated_plaintext_data\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.associated_plaintext_data))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.ciphertext_data != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"ciphertext_data\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.ciphertext_data)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.iv_data != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"iv_data\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.iv_data)).c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.gcm_authentication_tag_data != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"gcm_authentication_tag_data\\\":\\\"");
        BLE_SendMessage(
            add_that_json(
                add_that_json(sent_message.gcm_authentication_tag_data))
                .c_str());
        BLE_SendMessage("\\\"");
    }
    if (sent_message.device_signature != "")
    {
        if (first)
        {
            first = false;
        }
        else
            BLE_SendMessage(", ");
        BLE_SendMessage("\\\"device_signature\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(sent_message.device_signature))
                .c_str());
        BLE_SendMessage("\\\"");
    }
}

void DeviceController::send_xxx_message(const string &message_operation,
                                        const string &message_type,
                                        const RTicket &sent_message)
{
    // ????
    printf("[M2354] info: %s is sending message...\n", shared_data->this_device.device_name.c_str());
    if ((message_operation == message::MESSAGE_RECV_AND_STORE ||
         message_operation == message::MESSAGE_VERIFY_AND_EXECUTE) &&
        (message_type == u_ticket::MESSAGE_TYPE ||
         message_type == r_ticket::MESSAGE_TYPE))
    {
        try
        {

            BLE_SendMessage("{\"message_operation\":\"");
            BLE_SendMessage(add_that_json(message_operation).c_str());
            BLE_SendMessage("\",\"message_type\":\"");
            BLE_SendMessage(add_that_json(message_type).c_str());
            BLE_SendMessage("\",\"message_str\":\"{");
            print_that_ticket(sent_message);
            BLE_SendMessage("}\"}$");
        }
        catch (const std::exception &error)
        {
            printf("error: %s\n", error.what());
            throw std::runtime_error("Weird M-Request: " +
                                     string(error.what()));
        }
    }
    else
    {
        throw std::runtime_error("Weird M-Request");
    }
}

// bool ReceiveMessage(char *buffer, int bufferSize) {
//     int index = 0;
//     while (index < bufferSize - 1) {
//         if (UART_IS_RX_READY(UART0)) {
//             char receivedChar = UART_READ(UART0);
//             if (receivedChar == '\n' || receivedChar == '\r') {
//                 break;
//             }
//             buffer[index++] = receivedChar;
//         }
//     }
//     buffer[index] = '\0'; // 確保字符串結束
//     return index > 0;
// }

void DeviceController::self_device_recv_permissionless()
{
    BLE_SendMessage("{\"message_operation\":\"PERMISSIONLESS\",");
    BLE_SendMessage("\"message_type\":\"RTICKET\",");
    BLE_SendMessage("\"message_str\":\"");
    for (int i = 0; i < candidate_num; i++)
    {
        if (i == 0)
        {
            BLE_SendMessage("{\\\"candidate_");
        }
        else
        {
            BLE_SendMessage(",\\\"candidate_");
        }
        BLE_SendMessage(to_string(i).c_str());
        BLE_SendMessage("\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(voting_candidates[i].first)).c_str());
        if (voting_state == VOTING_STATE::BEFORE_VOTING)
        {
            BLE_SendMessage(", ");
            BLE_SendMessage(to_string(voting_candidates[i].second).c_str());
        }
        BLE_SendMessage("\\\"");
    }
    for (int i = 0; i < voter_num; i++)
    {
        BLE_SendMessage(",\\\"voter_");
        BLE_SendMessage(to_string(i).c_str());
        BLE_SendMessage("\\\":\\\"");
        BLE_SendMessage(
            add_that_json(add_that_json(voting_voters[i].first)).c_str());
        if (voting_state == VOTING_STATE::BEFORE_VOTING)
        {
            BLE_SendMessage(", ");
            BLE_SendMessage(voting_voters[i].second ? "voted" : "not voted");
        }
        BLE_SendMessage("\\\"");
    }
    if (candidate_num != 0 && voter_num != 0)
    {
        BLE_SendMessage("}");
    }
    BLE_SendMessage("\"");
    BLE_SendMessage("}$");
}

void DeviceController::recv_xxx_message_ble(char *received_msg)
{
    /* while (true) { */
    // ???????????
    // 確保波特率與 Python 端匹配
    // received_msg = (char *)malloc(1000);
    // read_flag = 1;
    try
    {

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (shared_data->simulated_comm_completed_flag == true)
            {
                /* break; */
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            /* break; */
        }

        // [STAGE (R)]

        if (Environment::COMMUNICATION_CHANNEL == "SIMULATED")
        {
            if (Environment::DEPLOYMENT_ENV == "TEST")
            {
                // received_msg = (char *)SIMULATED_GLOBAL_CHANNEL.c_str();
                // printf("This is What I Want\\n%s\n", received_msg);
                // SIMULATED_GLOBAL_CHANNEL = "";
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
            else if (Environment::DEPLOYMENT_ENV == "PRODUCTION")
            {
                // received_message_with_header =
                // shared_data->simulated_comm_channel.receiver_queue.front();
                // shared_data->simulated_comm_channel.receiver_queue.pop();
            }
        }
        else if (Environment::COMMUNICATION_CHANNEL == "BLUETOOTH")
        {
            // received_message_with_header =
            // shared_data->connection_socket.receiveMessage();
        }
        else if (Environment::COMMUNICATION_CHANNEL == "UART")
        {
            // printf("\n\nWaiting PC Sending Ticket\n\n");
            // if (ReceiveMessage(received_message_with_header, 1000)) {
            //     printf("[M2354] Received: %s\n\n",received_message_with_header);
            // }
        }
        if (received_msg == NULL)
        {
            throw std::runtime_error("[M2354] Received message is empty");
        }

        printf("[M2354] iot_device Received Message\n");

        // printf("cli Received Message: %s\n\n",
        // received_message_with_header);
        char *received_without_header = (char *)malloc(900);
        memset(received_without_header, 0, 900);
        // printf("有沒有來這\n");
        int which_ticket = self_classify_message_is_defined_type(
            received_msg, received_without_header);

        printf("[M2354] Received: %s\n", received_without_header);

        // free(received_msg);
        received_msg = NULL;
        pfNonSecure_Free(which_ticket);

        if (which_ticket == 1)
        {

            // printf("[M2354] Received: %s\n", received_without_header);
            UTicket received_u_ticket = u_ticket_verify_json_schema(
                (const char *)received_without_header);
            free(received_without_header);
            free(received_msg);
            self_classify_u_ticket_is_defined_type(received_u_ticket);
            // [STAGE (U)]
            // shared_data->received_message_json =
            //     received_u_ticket.to_json_str();
            if (shared_data->state == this_device::STATE_DEVICE_WAIT_FOR_UT)
            {
                self_device_recv_u_ticket(received_u_ticket);
            }
            else if (shared_data->state ==
                     this_device::STATE_DEVICE_WAIT_FOR_CMD)
            {
                self_device_recv_cmd(received_u_ticket);
            }
            else
            {
                throw std::runtime_error("[M2354] (MsgReceiver) Shouldn't Reach Here");
            }
        }
        else if (which_ticket == 2)
        {
            RTicket received_r_ticket =
                r_ticket_verify_json_schema(received_without_header);
            free(received_without_header);
            free(received_msg);
            self_classify_r_ticket_is_defined_type(received_r_ticket);
            // [STAGE (R)]
            // shared_data->received_message_json =
            //     received_r_ticket.to_json_str();
            if (shared_data->state ==
                this_device::STATE_DEVICE_WAIT_FOR_CRKE2)
            {
                self_device_recv_cr_ke_2(received_r_ticket);
            }
            else
            {
                throw std::runtime_error("[M2354] (MsgReceiver) Shouldn't Reach Here");
            }
        }
        else if (which_ticket == -1)
        {
            // permission less ticket logic
            self_device_recv_permissionless();
        }
    }

    // IOT device
    // printf("device_type: %s state: %s\n",  shared_data->this_device.device_type.c_str(), shared_data->state.c_str());

    catch (const std::runtime_error &error)
    {
        if (received_msg)
        {
            free(received_msg);
            received_msg = NULL;
            pfNonSecure_Free(-2);
        }
        shared_data->result_message = error.what();
        throw;
    }
    catch (...)
    {
        if (received_msg)
        {
            free(received_msg);
            received_msg = NULL;
            pfNonSecure_Free(-2);
        }
        throw std::runtime_error("[M2354] (MsgReceiver) Shouldn't Reach Here");
    }
    /* } */
}

void DeviceController::self_device_recv_u_ticket(UTicket &received_u_ticket)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (SR)]
        // no need to optionally _store_received_xxx_u_ticket

        // [STAGE: (VUT)]
        verify_u_ticket_can_execute(received_u_ticket);
        shared_data->result_message = " -> SUCCESS: VERIFY_UT_CAN_EXECUTE";
        // printf("info: start %s\n", shared_data->result_message.c_str());

        // UT-RT
        if (received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_INITIALIZATION_UTICKET ||
            received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            //[STAGE: (EO)]
            self_execute_xxx_u_ticket(received_u_ticket);
            // [STAGE: (C)]
            self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        }
        else if (received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_ACCESS_UTICKET ||
                 received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (E)]
            RTicket empty_r_ticket;
            self_execute_cr_ke(1, received_u_ticket, empty_r_ticket, "device");

            // [STAGE: (C)]
            self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CRKE2);
        }
        else
        {
            throw invalid_argument("[M2354] (self_device_recv_u_ticket) should not reach here");
        }

        // error
        //  TODO

        if (received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_INITIALIZATION_UTICKET ||
            received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(received_u_ticket.u_ticket_type,
                                      received_u_ticket.u_ticket_id,
                                      shared_data->result_message);
        }
        else if (received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_ACCESS_UTICKET ||
                 received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_cr_ke_1(shared_data->result_message);
        }
        else
        {
            throw invalid_argument("[M2354] (self_device_recv_u_ticket) should not reach here");
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        // [STAGE: (C)]
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);

        if (received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_INITIALIZATION_UTICKET ||
            received_u_ticket.u_ticket_type ==
                u_ticket::TYPE_OWNERSHIP_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(received_u_ticket.u_ticket_type,
                                      received_u_ticket.u_ticket_id,
                                      shared_data->result_message);
        }
        else if (received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_ACCESS_UTICKET ||
                 received_u_ticket.u_ticket_type ==
                     u_ticket::TYPE_SELFACCESS_UTICKET)
        {
            // [STAGE: (G)(S)]
            self_device_send_cr_ke_1(shared_data->result_message);
        }
        else
        {
            throw invalid_argument("[M2354] (self_device_recv_u_ticket) should not reach here");
        }
    }
}

RTicket DeviceController::self_device_send_r_ticket_generate_request(
    const string &u_ticket_type, const string &u_ticket_id,
    const string &result_message)
{
    // json generated_request;

    // generated_request.addValueString("r_ticket_type", u_ticket_type);
    // generated_request.addValueString("device_id",
    //                                  shared_data->this_device.device_pub_key);
    // generated_request.addValueString("result", result_message);
    // if (u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
    //     u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET) {
    //     if (result_message.find("SUCCESS") != string::npos) {
    //         generated_request.addValueString("audit_start", u_ticket_id);
    //     }
    // } else if (u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN) {
    //     if (result_message.find("SUCCESS") != string::npos) {
    //         generated_request.addValueString(
    //             "audit_start",
    //             shared_data->current_session.current_u_ticket_id);
    //         generated_request.addValueString("audit_end", "ACCESS_END");
    //     }
    // } else {
    //     throw invalid_argument(
    //         "self_device_send_r_ticket: should not reach here");
    // }

    RTicket generated_request;
    generated_request.r_ticket_type = u_ticket_type;
    generated_request.device_id = shared_data->this_device.device_pub_key;
    generated_request.result = result_message;
    if (u_ticket_type == u_ticket::TYPE_INITIALIZATION_UTICKET ||
        u_ticket_type == u_ticket::TYPE_OWNERSHIP_UTICKET)
    {
        if (result_message.find("SUCCESS") != string::npos)
        {
            generated_request.audit_start = u_ticket_id;
        }
    }
    else if (u_ticket_type == u_ticket::TYPE_ACCESS_END_UTOKEN)
    {
        if (result_message.find("SUCCESS") != string::npos)
        {
            generated_request.audit_start =
                shared_data->current_session.current_u_ticket_id;
            generated_request.audit_end = "ACCESS_END";
        }
    }
    else
    {
        throw invalid_argument(
            "[M2354] self_device_send_r_ticket: should not reach here");
    }

    return generated_request;
}

void DeviceController::self_device_send_r_ticket(const string &u_ticket_type,
                                                 const string &u_ticket_id,
                                                 const string &result_message)
{
    // [STAGE: (G)]
    RTicket received_r_ticket = self_device_send_r_ticket_generate_request(
        u_ticket_type, u_ticket_id, result_message);
    self_generate_xxx_r_ticket(received_r_ticket);
    // printf("generated_r_ticket_json: %s\n", generated_r_ticket_json.c_str());
    //  cout << "debug: generated_r_ticket_json: " <<
    //  generated_r_ticket_json <<
    //  "\n";
    //   [STAGE: (S)]
    send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE,
                     r_ticket::MESSAGE_TYPE, received_r_ticket);
}

void DeviceController::self_device_recv_cmd(UTicket &received_u_token)
{
    try
    {
        // [STAGE: (R)(VR)]
        // [STAGE: (VUT)]

        verify_u_ticket_can_execute(received_u_token);
        // [STAGE: (VTK)(VTS)]
        // [STAGE: (E)]
        self_execute_xxx_u_ticket(received_u_token);

        shared_data->result_message = "-> SUCCESS: VERIFY_UT_CAN_EXECUT";

        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (C)]
            self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        }
        else if (received_u_token.u_ticket_type ==
                 u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (C)]
            self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        }
        else
        {
            throw std::runtime_error("[M2354] (self_device_recv_cmd) Shouldn't Reach Here");
        }

        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }
        else if (received_u_token.u_ticket_type ==
                 u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(received_u_token.u_ticket_type,
                                      received_u_token.u_ticket_id,
                                      shared_data->result_message);
        }
        else
        {
            throw std::runtime_error("[M2354] (self_device_recv_cmd) Shouldn't Reach Here");
        }
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);
        if (received_u_token.u_ticket_type == u_ticket::TYPE_CMD_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_data(shared_data->result_message);
        }
        else if (received_u_token.u_ticket_type ==
                 u_ticket::TYPE_ACCESS_END_UTOKEN)
        {
            // [STAGE: (G)(S)]
            self_device_send_r_ticket(received_u_token.u_ticket_type,
                                      received_u_token.u_ticket_id,
                                      shared_data->result_message);
            shared_data->current_session.clear_session();
        }
        else
        {
            throw std::runtime_error("[M2354] (self_device_recv_cmd) Shouldn't Reach Here");
        }
    }
    catch (...)
    {
        throw std::runtime_error("[M2354] (self_device_recv_cmd) Shouldn't Reach Here");
    }
}
void DeviceController::self_device_send_data(const string &result_message)
{
    try
    {
        // [STAGE: (G)]

        RTicket generated_request;
        if (result_message.find("SUCCESS") != string::npos)
        {
            generated_request.r_ticket_type = r_ticket::TYPE_DATA_RTOKEN;
            generated_request.device_id =
                shared_data->this_device.device_pub_key;
            generated_request.result = result_message;
            generated_request.audit_start =
                shared_data->current_session.current_u_ticket_id;
            generated_request.associated_plaintext_data =
                shared_data->current_session.associated_plaintext_data;
            generated_request.ciphertext_data =
                shared_data->current_session.ciphertext_data;
            generated_request.gcm_authentication_tag_data =
                shared_data->current_session.gcm_authentication_tag_data;
            generated_request.iv_cmd = shared_data->current_session.iv_cmd;
        }
        else
        {
            generated_request.r_ticket_type = r_ticket::TYPE_DATA_RTOKEN;
            generated_request.device_id =
                shared_data->this_device.device_pub_key;
            generated_request.result = result_message;
        }

        self_generate_xxx_r_ticket(generated_request);

        // [STAGE: (S)]
        send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE,
                         r_ticket::MESSAGE_TYPE, generated_request);
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = "FAILURE: (C)";
        throw;
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

bool check_result(const string &target, const string &result_message)
{
    return result_message.find(target) != string::npos;
}

void DeviceController::self_device_send_cr_ke_1(const string &result_message)
{
    // [STAGE: (G)]

    RTicket r_ticket_request;

    if (check_result("SUCCESS", result_message))
    {
        r_ticket_request.r_ticket_type = r_ticket::TYPE_CRKE1_RTICKET;
        r_ticket_request.device_id = shared_data->this_device.device_pub_key;
        r_ticket_request.result = result_message;
        r_ticket_request.audit_start =
            shared_data->current_session.current_u_ticket_id;
        r_ticket_request.challenge_1 = shared_data->current_session.challenge_1;
        r_ticket_request.key_exchange_salt_1 =
            shared_data->current_session.key_exchange_salt_1;
        r_ticket_request.iv_cmd = shared_data->current_session.iv_cmd;
    }
    else
    {
        r_ticket_request.r_ticket_type = r_ticket::TYPE_CRKE1_RTICKET;
        r_ticket_request.device_id = shared_data->this_device.device_pub_key;
        r_ticket_request.result = result_message;
    }

    // cout << "Are you here? " << r_ticket_request.dump() << "\n";

    self_generate_xxx_r_ticket(r_ticket_request);
    // [STAGE: (S)]
    send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE,
                     r_ticket::MESSAGE_TYPE, r_ticket_request);
}

void DeviceController::self_device_recv_cr_ke_2(RTicket &received_r_ticket)
{
    try
    {
        // [STAGE: (VRT)]
        UTicket empty_u_ticket;
        verify_u_ticket_has_executed_through_r_ticket(
            received_r_ticket, empty_u_ticket, empty_u_ticket);

        // [STAGE: (E)]
        self_execute_xxx_r_ticket(received_r_ticket, "holder-or-device");

        shared_data->result_message = "SUCCESS: VERIFY_UT_HAS_EXECUTED";

        // [STAGE: (C)]
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_CMD);

        // [STAGE: (G)(S)]
        self_device_send_cr_ke_3(shared_data->result_message);
    }
    catch (const std::runtime_error &e)
    {
        shared_data->result_message = e.what();
        self_change_state(this_device::STATE_DEVICE_WAIT_FOR_UT);
        // [STATE: (G)(S)]
        self_device_send_cr_ke_3(shared_data->result_message);
    }
    catch (...)
    {
        throw std::runtime_error("Shouldn't Reach Here");
    }
}

void DeviceController::self_device_send_cr_ke_3(const string &result_message)
{
    // [STAGE: (G)]

    RTicket r_ticket_request;

    if (check_result("SUCCESS", result_message))
    {
        r_ticket_request.r_ticket_type = r_ticket::TYPE_CRKE3_RTICKET;
        r_ticket_request.device_id = shared_data->this_device.device_pub_key;
        r_ticket_request.result = result_message;
        r_ticket_request.audit_start =
            shared_data->current_session.current_u_ticket_id;
        r_ticket_request.challenge_2 = shared_data->current_session.challenge_2;
        r_ticket_request.key_exchange_salt_2 =
            shared_data->current_session.key_exchange_salt_2;
        r_ticket_request.associated_plaintext_data =
            shared_data->current_session.associated_plaintext_data;
        r_ticket_request.ciphertext_data =
            shared_data->current_session.ciphertext_data;
        r_ticket_request.gcm_authentication_tag_data =
            shared_data->current_session.gcm_authentication_tag_data;
        r_ticket_request.iv_cmd = shared_data->current_session.iv_cmd;
    }
    else
    {
        r_ticket_request.r_ticket_type = r_ticket::TYPE_CRKE3_RTICKET;
        r_ticket_request.device_id = shared_data->this_device.device_pub_key;
        r_ticket_request.result = result_message;
    }

    self_generate_xxx_r_ticket(r_ticket_request);

    // [STAGE: (S)]
    send_xxx_message(message::MESSAGE_VERIFY_AND_EXECUTE,
                     r_ticket::MESSAGE_TYPE, r_ticket_request);
}

DeviceController::DeviceController(const string &device_type,
                                   const string &device_name)
{
    initialize();

    if (!shared_data->this_device.has_device_type)
    {
        self_execute_one_time_set_time_device_type_and_name(device_type,
                                                            device_name);
        printf("[M2354] info: Set device type and name to %s, %s\n", device_type.c_str(), device_name.c_str());
    }

    self_initialize_state();

    printf("[M2354] info: Here is a %s...\n", shared_data->this_device.device_name.c_str());
}

DeviceController::~DeviceController() { cleanup(); }

void DeviceController::reboot_device()
{
    printf("[M2354] info: Reboot %s...\n", shared_data->this_device.device_name.c_str());
    cleanup();
    initialize();
}

void DeviceController::initialize() { shared_data = new SharedData(); }

void DeviceController::cleanup() { delete shared_data; }

string add_that_json(const string &input)
{
    // parse input, if \, " appears, add \ after it
    string escaped;
    for (char c : input)
    {
        switch (c)
        {
        case '\"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        default:
            escaped += c;
            break;
        }
    }
    return escaped;
}

string CurrentSession::to_json()
{
    json j;
    if (!current_u_ticket_id.empty())
        j.addValueString("current_u_ticket_id", current_u_ticket_id);
    if (!current_device_id.empty())
        j.addValueString("current_device_id", current_device_id);
    if (!current_holder_id.empty())
        j.addValueString("current_holder_id", current_holder_id);
    if (!current_task_scope.empty())
        j.addValueString("current_task_scope", current_task_scope);

    if (!challenge_1.empty())
        j.addValueString("challenge_1", challenge_1);
    if (!challenge_2.empty())
        j.addValueString("challenge_2", challenge_2);
    if (!key_exchange_salt_1.empty())
        j.addValueString("key_exchange_salt_1", key_exchange_salt_1);
    if (!key_exchange_salt_2.empty())
        j.addValueString("key_exchange_salt_2", key_exchange_salt_2);

    if (!current_session_key_str.empty())
        j.addValueString("current_session_key_str", current_session_key_str);
    if (!plaintext_cmd.empty())
        j.addValueString("plaintext_cmd", plaintext_cmd);
    if (!associated_plaintext_cmd.empty())
        j.addValueString("associated_plaintext_cmd", associated_plaintext_cmd);
    if (!iv_cmd.empty())
        j.addValueString("iv_cmd", iv_cmd);
    if (!ciphertext_cmd.empty())
        j.addValueString("ciphertext_cmd", ciphertext_cmd);
    if (!gcm_authentication_tag_cmd.empty())
        j.addValueString("gcm_authentication_tag_cmd",
                         gcm_authentication_tag_cmd);

    if (!plaintext_data.empty())
        j.addValueString("plaintext_data", plaintext_data);
    if (!associated_plaintext_data.empty())
        j.addValueString("associated_plaintext_data",
                         associated_plaintext_data);
    if (!iv_data.empty())
        j.addValueString("iv_data", iv_data);
    if (!ciphertext_data.empty())
        j.addValueString("ciphertext_data", ciphertext_data);
    return j.dump();
}

CurrentSession json_to_current_session(json j)
{
    CurrentSession session;

    return session;
}

string OtherDevice::to_json()
{
    json j;
    if (device_id != "")
        j.addValueString("device_id", device_id);
    if (ticket_order != 0)
        j.addValueInt("ticket_order", ticket_order);
    if (device_u_ticket_for_owner != "")
        j.addValueString("device_u_ticket_for_owner",
                         device_u_ticket_for_owner);
    if (device_ownership_u_ticket_for_others != "")
        j.addValueString("device_ownership_u_ticket_for_others",
                         device_ownership_u_ticket_for_others);
    if (device_access_u_ticket_for_others != "")
        j.addValueString("device_access_u_ticket_for_others",
                         device_access_u_ticket_for_others);
    if (device_r_ticket_for_owner != "")
        j.addValueString("device_r_ticket_for_owner",
                         device_r_ticket_for_owner);
    if (device_ownership_r_ticket_for_others != "")
        j.addValueString("device_ownership_r_ticket_for_others",
                         device_ownership_r_ticket_for_others);
    if (device_access_end_r_ticket_for_others != "")
        j.addValueString("device_access_end_r_ticket_for_others",
                         device_access_end_r_ticket_for_others);
    return j.dump();
}

OtherDevice json_to_other_device(json j)
{
    OtherDevice device;
    // device.device_id = j["device_id"];
    // device.ticket_order = j["ticket_order"];
    // device.device_u_ticket_for_owner = j["device_u_ticket_for_owner"];
    // device.device_ownership_u_ticket_for_others =
    // j["device_ownership_u_ticket_for_others"];
    // device.device_access_u_ticket_for_others =
    // j["device_access_u_ticket_for_others"];
    // device.device_r_ticket_for_owner = j["device_r_ticket_for_owner"];
    // device.device_ownership_r_ticket_for_others =
    // j["device_ownership_r_ticket_for_others"];
    // device.device_access_end_r_ticket_for_others =
    // j["device_access_end_r_ticket_for_others"];
    return device;
}

// mbedtls_ecdsa_context ThisDevice::strings_to_pp_keys()
// {
//     return turn_string_to_key(device_priv_key.c_str(),
//     device_pub_key.c_str());
// }

string ThisDevice::to_json()
{
    json j;
    if (device_priv_key != "")
        j.addValueString("device_priv_key", device_priv_key);
    if (device_pub_key != "")
        j.addValueString("device_pub_key", device_pub_key);
    if (owner_pub_key != "")
        j.addValueString("owner_pub_key", owner_pub_key);
    if (device_type != "")
        j.addValueString("device_type", device_type);
    if (device_name != "")
        j.addValueString("device_name", device_name);
    j.addValueBool("has_device_type", has_device_type);
    if (ticket_order != 0)
        j.addValueInt("ticket_order", ticket_order);

    return j.dump();
}

ThisDevice json_to_this_device(json j)
{
    ThisDevice device;
    // device.device_priv_key = j["device_priv_key"];
    // device.device_pub_key = j["device_pub_key"];
    // device.owner_pub_key = j["owner_pub_key"];
    // device.device_type = j["device_type"];
    // device.device_name = j["device_name"];
    // device.has_device_type = j["has_device_type"];
    // device.ticket_order = j["ticket_order"];
    return device;
}

// mbedtls_ecdsa_context ThisPerson::strings_to_pp_keys()
// {
//     return turn_string_to_key(person_priv_key.c_str(),
//     person_pub_key.c_str());
// }

// turn class into json
string ThisPerson::to_json()
{
    // use nlohmann json library
    json j;
    if (person_priv_key != "")
        j.addValueString("person_priv_key", person_priv_key);
    if (person_pub_key != "")
        j.addValueString("person_pub_key", person_pub_key);
    string json_str = j.dump();
    return json_str;
}

ThisPerson json_to_this_person(json j)
{
    ThisPerson person;
    // person.person_priv_key = j["person_priv_key"];
    // person.person_pub_key = j["person_pub_key"];
    return person;
}

string RTicket::to_json_str()
{
    string json_str = "{";
    if (protocol_version != "")
        json_str +=
            "\"protocol_version\":\"" + add_that_json(protocol_version) + "\",";
    if (r_ticket_id != "")
        json_str += "\"r_ticket_id\":\"" + add_that_json(r_ticket_id) + "\",";
    if (r_ticket_type != "")
        json_str +=
            "\"r_ticket_type\":\"" + add_that_json(r_ticket_type) + "\",";
    if (device_id != "")
        json_str += "\"device_id\":\"" + add_that_json(device_id) + "\",";
    if (result != "") // result is a string
        json_str += "\"result\":\"" + add_that_json(result) + "\",";
    json_str += "\"ticket_order\":" + to_string(ticket_order) + ",";
    if (audit_start != "")
        json_str += "\"audit_start\":\"" + add_that_json(audit_start) + "\",";
    if (audit_end != "")
        json_str += "\"audit_end\":\"" + add_that_json(audit_end) + "\",";
    if (challenge_1 != "")
        json_str += "\"challenge_1\":\"" + add_that_json(challenge_1) + "\",";
    if (challenge_2 != "")
        json_str += "\"challenge_2\":\"" + add_that_json(challenge_2) + "\",";
    if (key_exchange_salt_1 != "")
        json_str += "\"key_exchange_salt_1\":\"" +
                    add_that_json(key_exchange_salt_1) + "\",";
    if (key_exchange_salt_2 != "")
        json_str += "\"key_exchange_salt_2\":\"" +
                    add_that_json(key_exchange_salt_2) + "\",";
    if (associated_plaintext_cmd != "")
        json_str += "\"associated_plaintext_cmd\":\"" +
                    add_that_json(associated_plaintext_cmd) + "\",";
    if (ciphertext_cmd != "")
        json_str +=
            "\"ciphertext_cmd\":\"" + add_that_json(ciphertext_cmd) + "\",";
    if (iv_cmd != "")
        json_str += "\"iv_cmd\":\"" + add_that_json(iv_cmd) + "\",";
    if (gcm_authentication_tag_cmd != "")
        json_str += "\"gcm_authentication_tag_cmd\":\"" +
                    add_that_json(gcm_authentication_tag_cmd) + "\",";
    if (associated_plaintext_data != "")
        json_str += "\"associated_plaintext_data\":\"" +
                    add_that_json(associated_plaintext_data) + "\",";
    if (ciphertext_data != "")
        json_str +=
            "\"ciphertext_data\":\"" + add_that_json(ciphertext_data) + "\",";
    if (iv_data != "")
        json_str += "\"iv_data\":\"" + add_that_json(iv_data) + "\",";
    if (gcm_authentication_tag_data != "")
        json_str += "\"gcm_authentication_tag_data\":\"" +
                    add_that_json(gcm_authentication_tag_data) + "\",";
    if (device_signature != "")
        json_str +=
            "\"device_signature\":\"" + add_that_json(device_signature) + "\",";

    if (json_str.back() == ',')
        json_str.pop_back();
    json_str += "}";

    // printf("她媽有沒有變小: %s\n", json_str.c_str());

    return json_str; // Indentation of 4 spaces
}

void rticket_from_json_str(const string &json_str, RTicket &ticket)
{

    // printf("rticket_from_json_str: %s\n", json_str.c_str());
    json j;
    j.parse(json_str);
    int idx = -1;

    idx = j.find("protocol_version");
    if (idx != -1)
        ticket.protocol_version = j.get_string(idx);
    idx = j.find("r_ticket_id");
    if (idx != -1)
        ticket.r_ticket_id = j.get_string(idx);
    idx = j.find("r_ticket_type");
    if (idx != -1)
        ticket.r_ticket_type = j.get_string(idx);
    idx = j.find("device_id");
    if (idx != -1)
        ticket.device_id = j.get_string(idx);
    idx = j.find("result");
    if (idx != -1)
        ticket.result = j.get_string(idx);
    idx = j.find("ticket_order");
    if (idx != -1)
        ticket.ticket_order = j.get_int(idx);
    idx = j.find("audit_start");
    if (idx != -1)
        ticket.audit_start = j.get_string(idx);
    idx = j.find("audit_end");
    if (idx != -1)
        ticket.audit_end = j.get_string(idx);
    idx = j.find("challenge_1");
    if (idx != -1)
        ticket.challenge_1 = j.get_string(idx);
    idx = j.find("challenge_2");
    if (idx != -1)
        ticket.challenge_2 = j.get_string(idx);
    idx = j.find("key_exchange_salt_1");
    if (idx != -1)
        ticket.key_exchange_salt_1 = j.get_string(idx);
    idx = j.find("key_exchange_salt_2");
    if (idx != -1)
        ticket.key_exchange_salt_2 = j.get_string(idx);
    idx = j.find("associated_plaintext_cmd");
    if (idx != -1)
        ticket.associated_plaintext_cmd = j.get_string(idx);
    idx = j.find("ciphertext_cmd");
    if (idx != -1)
        ticket.ciphertext_cmd = j.get_string(idx);
    idx = j.find("iv_cmd");
    if (idx != -1)
        ticket.iv_cmd = j.get_string(idx);
    idx = j.find("gcm_authentication_tag_cmd");
    if (idx != -1)
        ticket.gcm_authentication_tag_cmd = j.get_string(idx);
    idx = j.find("associated_plaintext_data");
    if (idx != -1)
        ticket.associated_plaintext_data = j.get_string(idx);
    idx = j.find("ciphertext_data");
    if (idx != -1)
        ticket.ciphertext_data = j.get_string(idx);
    idx = j.find("iv_data");
    if (idx != -1)
        ticket.iv_data = j.get_string(idx);
    idx = j.find("gcm_authentication_tag_data");
    if (idx != -1)
        ticket.gcm_authentication_tag_data = j.get_string(idx);
    idx = j.find("device_signature");
    if (idx != -1)
        ticket.device_signature = j.get_string(idx);

    // printf("rticket_from_json_str: %s\n", ticket.to_json_str().c_str());
}

void RTicket::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}

string UTicket::to_json_str()
{
    string json_str = "{";
    if (protocol_version != "")
        json_str +=
            "\"protocol_version\":\"" + add_that_json(protocol_version) + "\",";
    if (u_ticket_id != "")
        json_str += "\"u_ticket_id\":\"" + add_that_json(u_ticket_id) + "\",";
    if (u_ticket_type != "")
        json_str +=
            "\"u_ticket_type\":\"" + add_that_json(u_ticket_type) + "\",";
    if (device_id != "")
        json_str += "\"device_id\":\"" + add_that_json(device_id) + "\",";
    json_str += "\"ticket_order\":" + to_string(ticket_order) + ",";
    if (holder_id != "")
        json_str += "\"holder_id\":\"" + add_that_json(holder_id) + "\",";
    if (task_scope != "")
        json_str += "\"task_scope\":\"" + add_that_json(task_scope) + "\",";
    if (issuer_signature != "")
        json_str +=
            "\"issuer_signature\":\"" + add_that_json(issuer_signature) + "\",";
    if (associated_plaintext_cmd != "")
        json_str += "\"associated_plaintext_cmd\":\"" +
                    add_that_json(associated_plaintext_cmd) + "\",";
    if (ciphertext_cmd != "")
        json_str +=
            "\"ciphertext_cmd\":\"" + add_that_json(ciphertext_cmd) + "\",";
    if (gcm_authentication_tag_cmd != "")
        json_str += "\"gcm_authentication_tag_cmd\":\"" +
                    add_that_json(gcm_authentication_tag_cmd) + "\",";
    if (iv_data != "")
        json_str += "\"iv_data\":\"" + add_that_json(iv_data) + "\",";

    if (json_str.back() == ',')
        json_str.pop_back();

    json_str += "}";

    // printf("她媽有沒有變小 u: %s\n", json_str.c_str());

    return json_str;
}

void DeviceController::uticket_from_json_str(const string &json_str,
                                             UTicket &ticket)
{
    // json j;
    // printf("uticket_from_json_str: %s\n", json_str.c_str());
    parse_uticket(json_str, ticket);
}

string Message::to_json_str()
{
    json j;
    if (message_operation != "")
        j.addValueString("message_operation", message_operation);
    if (message_type != "")
        j.addValueString("message_type", message_type);
    if (message_str != "")
        j.addValueString("message_str", message_str);

    /* printf("message_operation: %s\n", message_operation.c_str());
    printf("message_type: %s\n", message_type.c_str());
    printf("message_str: %s\n", message_str.c_str()); */

    return j.dump();
}

void remove_something(char *msg)
{
    int write = 0; // 寫入指標
    int read = 0;  // 讀取指標

    while (msg[read] != '\0')
    {
        if (msg[read] == '\\' && msg[read + 1] != '\0')
        {
            char next = msg[read + 1];
            if (next == '\n' || next == '\"' || next == '\\')
            {
                msg[write++] = next;
                read += 2;
            }
            else
            {
                msg[write++] = msg[read++];
            }
        }
        else
        {
            msg[write++] = msg[read++];
        }
    }

    msg[write] = '\0'; // 將字串縮短到正確的長度並加上終止符
}

void message_from_json_str(const string &json_str, Message &msg)
{
    printf("[M2354] info: inside message_from_json_str %s\n", json_str.c_str());

    // json j;
    // j.parse(json_str);

    // int idx = -1;

    // idx = j.find("message_operation");
    // if (idx != -1)
    //     msg.message_operation = j.get_string(idx);
    // idx = j.find("message_type");
    // if (idx != -1)
    //     msg.message_type = j.get_string(idx);
    // idx = j.find("message_str");
    // if (idx != -1)
    //     msg.message_str = j.get_string(idx);

    string start_str = "\"message_str\":\"";
    string end_str = "}\"}";

    int start = json_str.find(start_str) + start_str.size();
    int end = json_str.find(end_str, start);
    msg.message_str = json_str.substr(start, end - start) + "}";
    // remove_something(msg.message_str);

    start_str = "\"message_type\":\"";
    end_str = "\",\"message_str\":\"";
    start = json_str.find(start_str) + start_str.size();
    end = json_str.find(end_str, start);
    msg.message_type = json_str.substr(start, end - start);

    start_str = "\"message_operation\":\"";
    end_str = "\",\"message_type\":\"";
    start = json_str.find(start_str) + start_str.size();
    end = json_str.find(end_str, start);
    msg.message_operation = json_str.substr(start, end - start);

    return;
}

void Message::validate_json(const json &j)
{
    // Implement validation logic here
    // For example, check for required fields, types, etc.
}

string byte_to_hex(unsigned char *bytes, int len)
{
    string hex_str = "";
    for (int i = 0; i < len; i++)
    {
        char hex_byte[3];
        sprintf(hex_byte, "%02x", bytes[i]);
        hex_str += hex_byte;
    }
    return hex_str;
}

string hex_to_byte(string hex_str)
{
    string byte_str = "";
    for (int i = 0; i < hex_str.size(); i += 2)
    {
        char byte = (char)strtol(hex_str.substr(i, 2).c_str(), NULL, 16);
        byte_str += byte;
    }
    return byte_str;
}

string gcm_gen_iv() { return generate_random_str(12); }

string generate_random_str(int bytes_num)
{
    unsigned char *random_bytes = new unsigned char[bytes_num / 2];
    for (int i = 0; i < bytes_num / 2; i++)
    {
        random_bytes[i] = rand() % 256;
    }
    string ret_base = byte_to_hex(random_bytes, bytes_num / 2);
    // check the size
    // cout << "random string: " << ret_str.size() << " and the size of byte
    // is"
    // << bytes_num << endl;
    printf("[M2354] random string: %d and the size of byte is %d\n", ret_base.size(), bytes_num);
    return ret_base;
}

void DeviceController::addStringToUTicket(const string &key,
                                          const string &value,
                                          UTicket &u_ticket)
{
    if (key == "protocol_version")
        u_ticket.protocol_version = value;
    else if (key == "u_ticket_id")
        u_ticket.u_ticket_id = value;
    else if (key == "u_ticket_type")
        u_ticket.u_ticket_type = value;
    else if (key == "device_id")
        u_ticket.device_id = value;
    else if (key == "holder_id")
        u_ticket.holder_id = value;
    else if (key == "task_scope")
        u_ticket.task_scope = value;
    else if (key == "issuer_signature")
        u_ticket.issuer_signature = value;
    else if (key == "associated_plaintext_cmd")
        u_ticket.associated_plaintext_cmd = value;
    else if (key == "ciphertext_cmd")
        u_ticket.ciphertext_cmd = value;
    else if (key == "gcm_authentication_tag_cmd")
        u_ticket.gcm_authentication_tag_cmd = value;
    else if (key == "iv_data")
        u_ticket.iv_data = value;
    else
    {
        printf("Invalid key: %s\n", key.c_str());
        throw std::runtime_error("Invalid key.");
    }
}

void DeviceController::parse_uticket(const string &jsonString,
                                     UTicket &u_ticket_in)
{
    // printf("Parsing JSON string: %s\n", jsonString.c_str());
    string key, value;
    bool isKey = true, inString = false, isEscaping = false, isBool = false,
         isInt = false;
    int braceCount = 1;

    if (jsonString.empty() || jsonString[0] != '{' ||
        jsonString.back() != '}')
    {
        printf("Invalid JSON format: JSON object must start with '{' and end with '}'.\n");
        throw std::runtime_error("Invalid JSON format: JSON object must start "
                                 "with '{' and end with '}'.");
    }

    for (int i = 1; i < jsonString.size(); ++i)
    {
        char c = jsonString[i];

        if (isEscaping)
        {
            if (c == '\\' || c == '\"')
            {
                (isKey) ? (key += c)
                        : (value += c); // Add the character directly if it's a
            }
            else
            {
                switch (c)
                {
                case 'n':
                    (isKey) ? (key += '\n') : (value += '\n');
                    break;
                default:
                    printf("Invalid escape sequence\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid escape sequence.");
                    break;
                }
            }
            isEscaping = false; // Reset escaping state
            continue;
        }

        if (c == '\\')
        {
            isEscaping = true;
            continue;
        }

        if (c == '\"')
        {
            inString = !inString; // Toggle inString state
            continue;
        }

        if (c >= '0' && c <= '9' && !isKey && !inString)
        {
            if (c == '0' && jsonString[i + 1] >= '0' &&
                jsonString[i + 1] <= '9')
            {
                printf("Invalid JSON format: Leading zeros are not allowed.\n");
                throw std::runtime_error(
                    "Invalid JSON format: Leading zeros are not allowed.");
            }
            int j = i + 1;
            int num = c - '0';
            while (j < jsonString.size() && jsonString[j] >= '0' &&
                   jsonString[j] <= '9')
            {
                num = num * 10 + (jsonString[j] - '0');
                j++;
            }
            while (jsonString[j] != ',' && jsonString[j] != '}' &&
                   j < jsonString.size())
                j++;

            if (j >= jsonString.size())
            {
                printf("Invalid JSON format: Missing comma or closing brace.\n");
                throw std::runtime_error(
                    "Invalid JSON format: Missing comma or closing brace.");
            }
            i = j;
            // addValueInt(key, num);
            if (key == "ticket_order")
            {
                u_ticket_in.ticket_order = num;
            }
            key.clear();
            value.clear();
            isKey = true;

            if (jsonString[j] == '}')
            {
                braceCount--;
                if (braceCount < 0)
                {
                    printf("Invalid JSON format: Unmatched closing brace.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Unmatched closing brace.");
                }
            }
            continue;
        }

        if ((c == 't' || c == 'f') && !inString && !isKey)
        {
            if (c == 't')
            {
                if (jsonString.substr(i, 4) == "true")
                {
                    // addValueBool(key, true);
                    i += 4;
                }
                else
                {
                    printf("Invalid JSON format: Invalid boolean value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid boolean value.");
                }
            }
            else
            {
                if (jsonString.substr(i, 5) == "false")
                {
                    // addValueBool(key, false);
                    i += 5;
                }
                else
                {
                    printf("Invalid JSON format: Invalid boolean value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Invalid boolean value.");
                }
            }
            key.clear();
            value.clear();
            isKey = true;
            continue;
        }

        if (inString)
        {
            (isKey) ? (key += c) : (value += c);
        }
        else
        {
            if (isspace(c))
            {
                continue;
            }
            if (c == ':')
            {
                if (!isKey || key.empty())
                {
                    printf("Invalid JSON format: Missing key or misplaced colon.\n");
                    throw std::runtime_error("Invalid JSON format: Missing "
                                             "key or misplaced colon.");
                }
                isKey = false;
                continue;
            }

            if (c == ',' || c == '}')
            {
                if (!key.empty() && !value.empty())
                {
                    // addValueString(key, value);
                    addStringToUTicket(key, value, u_ticket_in);
                }
                else if (!key.empty() && value.empty() &&
                         (c == '}' || c == ','))
                {
                    // addValueString(key, value);
                    addStringToUTicket(key, value, u_ticket_in);
                }
                else if (key.empty() && value.empty() && c == '}')
                {
                    break;
                }
                else
                {
                    printf("Invalid JSON format: Missing key or value.\n");
                    throw std::runtime_error(
                        "Invalid JSON format: Missing key or value.");
                }

                key.clear();
                value.clear();
                isKey = true;

                if (c == '}')
                {
                    braceCount--;
                    if (braceCount < 0)
                    {
                        printf("Invalid JSON format: Unmatched closing brace.\n");
                        throw std::runtime_error(
                            "Invalid JSON format: Unmatched closing "
                            "brace.");
                    }
                }
                continue;
            }
        }
    }

    if (braceCount != 0)
    {
        printf("Invalid JSON format: Unmatched opening brace.\n");
        throw std::runtime_error(
            "Invalid JSON format: Unmatched opening brace.");
    }

    if (inString)
    {
        printf("Invalid JSON format: Unclosed string.\n");
        throw std::runtime_error("Invalid JSON format: Unclosed string.");
    }

    if (!key.empty() || !value.empty())
    {
        // data.push_back(make_pair(key, value));
        addStringToUTicket(key, value, u_ticket_in);
    }
}
