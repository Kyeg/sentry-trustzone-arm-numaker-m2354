#include <NuMicro.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    256 /* NOTE: This value must be 16 bytes alignment. This value must > size \
of A */
#define MAX_GCM_BUF 512

#ifdef BLE
#define RXBUFSIZE 20
// BLE Global variables
char *received_msg;
volatile int read_flag = 0;
// static volatile uint32_t g_u32comRbytes = 0;
// static volatile uint32_t g_u32comRhead = 0;
volatile uint32_t g_u32comRtail = 0;
#endif

volatile int g_Crypto_Int_done = 0;
__ALIGNED(4)
uint8_t g_au8Buf[MAX_GCM_BUF];

__ALIGNED(4)
uint8_t g_au8Out2[MAX_GCM_BUF];
__ALIGNED(4)
uint8_t g_au8FeedBackBuf[72] = {0};

uint8_t Byte2Char(uint8_t c) {
    if (c < 10)
        return (c + '0');
    if (c < 16)
        return (c - 10 + 'a');

    return 0;
}

void CRPT_IRQHandler() {
    ECC_DriverISR(CRPT);
    if (AES_GET_INT_FLAG(CRPT)) {
        g_Crypto_Int_done = 1;
        AES_CLR_INT_FLAG(CRPT);
    }
}

void dump_buff_hex(uint8_t *pucBuff, int nBytes) {
    int nIdx, i;

    nIdx = 0;
    while (nBytes > 0) {
        printf("0x%04X  ", nIdx);
        for (i = 0; i < 16; i++)
            printf("%02x ", pucBuff[nIdx + i]);
        printf("  ");
        for (i = 0; i < 16; i++) {
            if ((pucBuff[nIdx + i] >= 0x20) && (pucBuff[nIdx + i] < 127))
                printf("%c", pucBuff[nIdx + i]);
            else
                printf(".");
            nBytes--;
        }
        nIdx += 16;
        printf("\n");
    }
    printf("\n");
}

void str2bin(const char *pstr, uint8_t *buf, uint32_t size) {
    uint32_t i;
    uint8_t u8Ch;
    char c;

    for (i = 0; i < size; i++) {
        c = *pstr++;
        if (c == NULL)
            break;

        if ((c >= 'a') && (c <= 'f'))
            c -= ('a' - 10);
        else if ((c >= 'A') && (c <= 'F'))
            c -= ('A' - 10);
        else if ((c >= '0') && (c <= '9'))
            c -= '0';
        u8Ch = (uint8_t)c << 4;

        c = *pstr++;
        if (c == NULL) {
            buf[i] = u8Ch;
            break;
        }

        if ((c >= 'a') && (c <= 'f'))
            c -= ('a' - 10);
        else if ((c >= 'A') && (c <= 'F'))
            c -= ('A' - 10);
        else if ((c >= '0') && (c <= '9'))
            c -= '0';
        u8Ch += (uint8_t)c;

        buf[i] = u8Ch;
    }
}

void bin2str(const uint8_t *in, size_t inLen, char *out) {
    for (size_t i = 0; i < inLen; i++)
        sprintf(out + i * 2, "%02X", in[i]); // 每 byte 轉 2 hex
    out[inLen * 2] = '\0';                   // 這行非常重要
}

int32_t ToBigEndian(uint8_t *pbuf, uint32_t u32Size) {
    uint32_t i;
    uint8_t u8Tmp;
    uint32_t u32Tmp;

    /* pbuf must be word alignment */
    if ((uint32_t)pbuf & 0x3) {
        printf("The buffer must be 32-bit alignment.");
        return -1;
    }

    while (u32Size >= 4) {
        u8Tmp = *pbuf;
        *(pbuf) = *(pbuf + 3);
        *(pbuf + 3) = u8Tmp;

        u8Tmp = *(pbuf + 1);
        *(pbuf + 1) = *(pbuf + 2);
        *(pbuf + 2) = u8Tmp;

        u32Size -= 4;
        pbuf += 4;
    }

    if (u32Size > 0) {
        u32Tmp = 0;
        for (i = 0; i < u32Size; i++) {
            u32Tmp |= *(pbuf + i) << (24 - i * 8);
        }

        *((uint32_t *)pbuf) = u32Tmp;
    }

    return 0;
}

int32_t ToLittleEndian(uint8_t *pbuf, uint32_t u32Size) {
    uint32_t i;
    uint8_t u8Tmp;
    uint32_t u32Tmp;

    /* pbuf must be word alignment */
    if ((uint32_t)pbuf & 0x3) {
        printf("The buffer must be 32-bit alignment.");
        return -1;
    }

    while (u32Size >= 4) {
        u8Tmp = *pbuf;
        *(pbuf) = *(pbuf + 3);
        *(pbuf + 3) = u8Tmp;

        u8Tmp = *(pbuf + 1);
        *(pbuf + 1) = *(pbuf + 2);
        *(pbuf + 2) = u8Tmp;

        u32Size -= 4;
        pbuf += 4;
    }

    if (u32Size > 0) {
        u32Tmp = 0;
        for (i = 0; i < u32Size; i++) {
            u32Tmp |= *(pbuf + i) << (24 - i * 8);
        }

        *((uint32_t *)pbuf) = u32Tmp;
    }

    return 0;
}

#define swap32(x)                                                              \
    (((x) & 0xff) << 24 | ((x) & 0xff00) << 8 | ((x) & 0xff0000) >> 8 |        \
     ((x) >> 24) & 0xff)
static void swap64(uint8_t *p) {
    uint8_t tmp;
    int32_t i;

    for (i = 0; i < 4; i++) {
        tmp = p[i];
        p[i] = p[7 - i];
        p[7 - i] = tmp;
    }
}

/*
NOTE: pbuf must be word alignment

    GCM input format must be block alignment. The block size is 16 bytes.
    {IV}{IV nbits}{A}{P/C}


*/

int32_t AES_GCMPacker(uint8_t *iv, uint32_t iv_len, uint8_t *A, uint32_t A_len,
                      uint8_t *P, uint32_t P_len, uint8_t *pbuf,
                      uint32_t *psize) {
    uint32_t i;
    uint32_t iv_len_aligned, A_len_aligned, P_len_aligned;
    uint32_t u32Offset = 0;
    uint8_t *pu8;

    /* IV Section:

       if bitlen(IV) == 96
         IV section = IV || 31'bit 0 || 1

       if bitlen(IV) != 96
         IV section = 128'align(IV) || 64'bit 0 || 64'bitlen(IV)
    */
    if (iv_len > 0) {
        iv_len_aligned = iv_len;
        if (iv_len & 0xful)
            iv_len_aligned = ((iv_len + 16) >> 4) << 4;

        /* fill iv to output */
        for (i = 0; i < iv_len_aligned; i++) {
            if (i < iv_len)
                pbuf[i] = iv[i];
            else
                pbuf[i] = 0; // padding zero
        }

        /* fill iv len to putput */
        if (iv_len == 12) {
            pbuf[15] = 1;
            u32Offset += iv_len_aligned;
        } else {
            /* Padding zero. 64'bit 0 */
            memset(&pbuf[iv_len_aligned], 0, 8);

            /* 64'bitlen(IV) */
            pu8 = &pbuf[iv_len_aligned + 8];
            *((uint64_t *)pu8) = iv_len * 8;
            swap64(pu8);
            u32Offset += iv_len_aligned + 16;
        }
    }

    /* A Section = 128'align(A) */
    if (A_len > 0) {
        A_len_aligned = A_len;
        if (A_len & 0xful)
            A_len_aligned = ((A_len + 16) >> 4) << 4;

        for (i = 0; i < A_len_aligned; i++) {
            if (i < A_len)
                pbuf[u32Offset + i] = A[i];
            else
                pbuf[u32Offset + i] = 0; // padding zero
        }

        u32Offset += A_len_aligned;
    }

    /* P/C Section = 128'align(P/C) */
    if (P_len > 0) {
        P_len_aligned = P_len;
        if (P_len & 0xful)
            P_len_aligned = ((P_len + 16) >> 4) << 4;

        for (i = 0; i < P_len_aligned; i++) {
            if (i < P_len)
                pbuf[u32Offset + i] = P[i];
            else
                pbuf[u32Offset + i] = 0; // padding zero
        }
        u32Offset += P_len_aligned;
    }

    *psize = u32Offset;

    return 0;
}

void AES_Run(uint32_t u32Option) {
    uint32_t u32TimeOutCnt;

    g_Crypto_Int_done = 0;
    CRPT->AES_CTL = u32Option | START;
    /* Waiting for AES calculation */
    u32TimeOutCnt = SystemCoreClock; /* 1 second time-out */
    while (!g_Crypto_Int_done) {
        if (--u32TimeOutCnt == 0) {
            printf("Wait for AES calculation done time-out!\n");
            break;
        }
    }
}

/*
    AES_GCMTag is only used by AES_GCMEnc to calculate tag.
*/
static void AES_GCMTag(uint8_t *key, uint32_t klen, uint8_t *iv, uint32_t ivlen,
                       uint8_t *A, uint32_t alen, uint8_t *P, uint32_t plen,
                       uint8_t *tagbuf) {
    int32_t i, len, plen_cur;
    uint8_t *pin, *pout;
    uint32_t inputblock[GCM_PBLOCK_SIZE * 2] = {
        0}; /* 2 block buffer, 1 for A, 1 for P */
    uint32_t ghashbuf[GCM_PBLOCK_SIZE + 16] = {0};
    uint8_t *pblock;
    uint32_t u32OptBasic;
    uint32_t u32OptKeySize;

    /* Prepare key size option */
    i = klen >> 3;
    u32OptKeySize = (((i >> 2) << 1) | (i & 1)) << CRPT_AES_CTL_KEYSZ_Pos;

    /* Basic options for AES */
    u32OptBasic = CRPT_AES_CTL_ENCRPT_Msk | CRPT_AES_CTL_INSWAP_Msk |
                  CRPT_AES_CTL_OUTSWAP_Msk | u32OptKeySize;

    /* Set byte count of IV */
    CRPT->AES_GCM_IVCNT[0] = ivlen;
    CRPT->AES_GCM_IVCNT[1] = 0;
    /* Set bytes count of A */
    CRPT->AES_GCM_ACNT[0] = alen;
    CRPT->AES_GCM_ACNT[1] = 0;
    /* Set bytes count of P */
    CRPT->AES_GCM_PCNT[0] = plen;
    CRPT->AES_GCM_PCNT[1] = 0;

    // GHASH(128'align(A) || 128'align(C) || 64'bitlen(A) || 64'bitlen(C))
    // GHASH Calculation
    if (plen <= GCM_PBLOCK_SIZE) {
        /* Just one shot if plen < maximum block size */

        pblock = (uint8_t *)&inputblock[0];
        AES_GCMPacker(0, 0, A, alen, P, plen, pblock, (uint32_t *)&len);

        /* append 64'bitlen(A) || 64'bitlen(C) */
        pblock += len;
        *((uint64_t *)pblock) = alen * 8;
        swap64(pblock);
        pblock += 8;

        *((uint64_t *)pblock) = plen * 8;
        swap64(pblock);
        pblock += 8;

        /* adding the length of 64'bitlen(A) and 64'bitlen(C) */
        len += 16;

        pblock = (uint8_t *)&inputblock[0];
        // printf("GHASH input (%d):\n", len);
        // dump_buff_hex(pblock, len);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)pblock, (uint32_t)&ghashbuf[0],
                           len);

        AES_Run(u32OptBasic | GHASH_MODE | DMAEN | DMALAST);

        // printf("GHASH output (%d):\n", len);
        // dump_buff_hex((uint8_t *)&ghashbuf[0], len);
    } else {
        /* Calculate GHASH block by block, DMA casecade mode */

        /* feedback buffer is necessary for casecade mode */
        CRPT->AES_FBADDR = (uint32_t)&g_au8FeedBackBuf[0];
        memset(g_au8FeedBackBuf, 0, sizeof(g_au8FeedBackBuf));

        /* inital DMA for GHASH casecade */
        if (alen) {
            /* Prepare the blocked buffer for GCM */
            AES_GCMPacker(0, 0, A, alen, 0, 0, g_au8Buf, (uint32_t *)&len);

            // printf("GHASH input (%d):\n", len);
            // dump_buff_hex(g_au8Buf, len);

            AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf,
                               (uint32_t)&ghashbuf[0], len);

            AES_Run(u32OptBasic | GHASH_MODE | FBOUT | DMAEN);
        }

        /* Caculate GHASH block by block */
        pin = P;
        pout = (uint8_t *)&ghashbuf[0];
        plen_cur = plen;
        len = GCM_PBLOCK_SIZE;
        while (plen_cur) {

            len = plen_cur;
            if (len > GCM_PBLOCK_SIZE)
                len = GCM_PBLOCK_SIZE;
            plen_cur -= len;

            if (plen_cur) {
                /* Sill has data for next block, it means current block size is
                 * full size */

                // printf("GHASH block input (%d):\n", len);
                // dump_buff_hex(pin, len);

                /* len should be alway 16 bytes alignment in here */
                AES_SetDMATransfer(CRPT, 0, (uint32_t)pin, (uint32_t)pout, len);

                AES_Run(u32OptBasic | GHASH_MODE | FBIN | FBOUT | DMAEN |
                        DMACC);
            } else {
                /* Next block data size is 0, it means current block size is not
                 * full size and this is last block */

                /* copy last C data to inputblock for zero padding */
                memcpy((uint8_t *)&inputblock[0], pin, len);
                pin = (uint8_t *)&inputblock[0];

                /* 16 bytes alignment check */
                if (len & 0xf) {
                    /* zero padding */
                    memset(pin + len, 0, 16 - (len & 0xf));

                    /* len must be 16 bytes alignment */
                    len = ((len + 16) >> 4) << 4;
                }

                /* append 64'bitlen(A) || 64'bitlen(C) */
                pblock = pin + len;
                *((uint64_t *)pblock) = alen * 8;
                swap64(pblock);
                pblock += 8;

                *((uint64_t *)pblock) = plen * 8;
                swap64(pblock);
                pblock += 8;

                /* adding the length of 64'bitlen(A) and 64'bitlen(C) */
                len += 16;

                // printf("GHASH block input (%d):\n", len);
                // dump_buff_hex(pin, len);

                AES_SetDMATransfer(CRPT, 0, (uint32_t)pin, (uint32_t)pout, len);

                AES_Run(u32OptBasic | GHASH_MODE | FBIN | FBOUT | DMAEN |
                        DMACC | DMALAST);
            }

            // printf("GHASH block output (%d):\n", len);
            // dump_buff_hex(pout, len);

            pin += len;
        }
    }

    // CTR(IV, GHASH(128'align(A) || 128'align(C) || 64'bitlen(A) ||
    // 64'bitlen(C))) CTR calculation

    /* Prepare IV */
    if (ivlen != 12) {
        uint32_t u32ivbuf[4] = {0};
        uint8_t *piv;

        // IV = GHASH(128'align(IV) || 64'bitlen(0) || 64'bitlen(IV))

        piv = (uint8_t *)&u32ivbuf[0];
        AES_GCMPacker(iv, ivlen, 0, 0, 0, 0, g_au8Buf, (uint32_t *)&len);

        // printf("IV GHASH input (%d):\n", len);
        // dump_buff_hex(g_au8Buf, len);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)piv, len);

        AES_Run(u32OptBasic | GHASH_MODE | DMAEN | DMALAST);

        // printf("IV GHASH output (%d):\n", len);
        // dump_buff_hex(piv, len);

        /* SET CTR IV */
        for (i = 0; i < 4; i++) {
            CRPT->AES_IV[i] = (piv[i * 4 + 0] << 24) | (piv[i * 4 + 1] << 16) |
                              (piv[i * 4 + 2] << 8) | piv[i * 4 + 3];
        }
    } else {
        // IV = 128'align(IV) || 31'bitlen(0) || 1

        /* SET CTR IV */
        for (i = 0; i < 3; i++) {
            CRPT->AES_IV[i] = (iv[i * 4 + 0] << 24) | (iv[i * 4 + 1] << 16) |
                              (iv[i * 4 + 2] << 8) | iv[i * 4 + 3];
        }
        CRPT->AES_IV[3] = 0x00000001;
    }

    AES_SetDMATransfer(CRPT, 0, (uint32_t)&ghashbuf[0], (uint32_t)&tagbuf[0],
                       16);

    AES_Run(u32OptBasic | CTR_MODE | DMAEN | DMALAST);

    //     printf("Tag calculation:\n");
    //     dump_buff_hex((uint8_t *)&tagbuf[0], 16);
}

int32_t AES_GCMEnc(uint8_t *key, uint32_t klen, uint8_t *iv, uint32_t ivlen,
                   uint8_t *A, uint32_t alen, uint8_t *P, uint32_t plen,
                   uint8_t *buf, uint32_t *size, uint32_t *plen_aligned) {
    int32_t plen_cur;
    int32_t len;
    uint8_t *pin, *pout;
    int32_t i, j;
    uint32_t u32OptKeySize;
    uint32_t u32OptBasic;
    uint32_t u32CTRIV[4] = {0};

    printf("\n");

    printf("key (%d):\n", klen);
    dump_buff_hex(key, klen);

    printf("IV (%d):\n", ivlen);
    dump_buff_hex(iv, ivlen);

    printf("A (%d):\n", alen);
    dump_buff_hex(A, alen);

    printf("P (%d):\n", plen);
    dump_buff_hex(P, plen);

    /* Prepare the key */
    memcpy(g_au8Buf, key, klen);
    ToBigEndian(g_au8Buf, klen);
    for (i = 0; i < klen / 4; i++) {
        CRPT->AES_KEY[i] = *((uint32_t *)&g_au8Buf[i * 4]);
    }

    /* Prepare key size option */
    i = klen >> 3;
    u32OptKeySize = (((i >> 2) << 1) | (i & 1)) << CRPT_AES_CTL_KEYSZ_Pos;

    /* Basic options for AES */
    u32OptBasic = CRPT_AES_CTL_ENCRPT_Msk | CRPT_AES_CTL_INSWAP_Msk |
                  CRPT_AES_CTL_OUTSWAP_Msk | u32OptKeySize;

    /* Set byte count of IV */
    CRPT->AES_GCM_IVCNT[0] = ivlen;
    CRPT->AES_GCM_IVCNT[1] = 0;

    /* Set bytes count of A */
    CRPT->AES_GCM_ACNT[0] = alen;
    CRPT->AES_GCM_ACNT[1] = 0;
    /* Set bytes count of P */
    CRPT->AES_GCM_PCNT[0] = plen;
    CRPT->AES_GCM_PCNT[1] = 0;

    *plen_aligned = (plen & 0xful) ? ((plen + 16) / 16) * 16 : plen;
    if (plen <= GCM_PBLOCK_SIZE) {
        /* Just one shot */

        /* Prepare the blocked buffer for GCM */
        AES_GCMPacker(iv, ivlen, A, alen, P, plen, g_au8Buf, size);

        // printf("input blocks (%d):\n", *size);
        // dump_buff_hex(g_au8Buf, *size);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)buf, *size);

        AES_Run(u32OptBasic | GCM_MODE | DMAEN | DMALAST);

        // printf("output blocks (%d):\n", *size);
        // dump_buff_hex(buf, *size);
    } else {

        /* Process P block by block, DMA casecade mode */

        /* inital DMA for AES-GCM casecade */

        /* Prepare the blocked buffer for GCM */
        AES_GCMPacker(iv, ivlen, A, alen, 0, 0, g_au8Buf, size);

        // printf("input blocks for casecade 0 (%d):\n", *size);
        // dump_buff_hex(g_au8Buf, *size);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)buf, *size);
        /* feedback buffer is necessary for casecade mode */
        CRPT->AES_FBADDR = (uint32_t)&g_au8FeedBackBuf[0];

        AES_Run(u32OptBasic | GCM_MODE | FBOUT | DMAEN);

        /* Start to encrypt P data */
        printf("P Block size for casecade mode %d\n", GCM_PBLOCK_SIZE);
        plen_cur = plen;
        pin = P;
        pout = buf;
        while (plen_cur) {
            len = plen_cur;
            if (len > GCM_PBLOCK_SIZE) {
                len = GCM_PBLOCK_SIZE;
            }
            plen_cur -= len;

            /* Prepare the blocked buffer for GCM */
            memcpy(g_au8Buf, pin, len);
            /* padding 0 if necessary */
            if (len & 0xf) {
                memset(&g_au8Buf[len], 0, 16 - (len & 0xf));
                len = ((len + 16) >> 4) << 4;
            }

            // printf("input blocks for casecade (%d):\n", len);
            // dump_buff_hex(g_au8Buf, len);

            AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)pout,
                               len);

            if (plen_cur) {
                /* casecade n */
                AES_Run(u32OptBasic | GCM_MODE | FBIN | FBOUT | DMAEN | DMACC);
            } else {
                /* last casecade */
                AES_Run(u32OptBasic | GCM_MODE | FBIN | FBOUT | DMAEN | DMACC |
                        DMALAST);
            }

            // printf("output blocks (%d):\n", len);
            // dump_buff_hex(pout, len);

            pin += len;
            pout += len;
        }

        /* Total size is plen aligment size + tag size */
        *size = *plen_aligned + 16;
    }

    /* Need to calculate Tag when plen % 16 == 1 or 15 */
    if (((plen & 0xf) == 1) || ((plen & 0xf) == 15)) {
        uint32_t tagbuf[4] = {0};

        AES_GCMTag(key, klen, iv, ivlen, A, alen, buf, plen,
                   (uint8_t *)&tagbuf[0]);

        /* Update tag to output buffer */
        memcpy(buf + *plen_aligned, (uint8_t *)&tagbuf[0], 16);
    }

    return 0;
}

int32_t AES_GCMDec(uint8_t *key, uint32_t klen, uint8_t *iv, uint32_t ivlen,
                   uint8_t *A, uint32_t alen, uint8_t *P,
                   uint32_t plen,  // ciphertext (可能含 tag), 允許 <16
                   uint8_t *buf,   // 解密輸出緩衝
                   uint32_t *size, // [out] 最終明文長度
                   uint32_t *plen_aligned) // block 對齊長度(若硬體需要)
{
    int32_t i, len, plen_cur;
    uint8_t *pin, *pout;
    uint32_t u32OptBasic;
    uint32_t u32OptKeySize;

    // [1] 不檢查 (plen < 16) return -1 了，允許更小 ciphertext
    //     可能表示沒有完整 16-byte tag

    /* Prepare key size option */
    i = klen >> 3;
    u32OptKeySize = (((i >> 2) << 1) | (i & 1)) << CRPT_AES_CTL_KEYSZ_Pos;

    /* Basic options for AES */
    u32OptBasic = CRPT_AES_CTL_INSWAP_Msk | CRPT_AES_CTL_OUTSWAP_Msk |
                  u32OptKeySize; // (解密)

    printf("\n[AES_GCMDec] ----------\n");
    printf("key (%u):\n", klen);
    dump_buff_hex(key, klen);

    printf("IV (%u):\n", ivlen);
    dump_buff_hex(iv, ivlen);

    printf("A  (%u):\n", alen);
    dump_buff_hex(A, alen);

    /* Set AES Key */
    memcpy(g_au8Buf, key, klen);
    ToBigEndian(g_au8Buf, klen);
    for (i = 0; i < (int)(klen / 4); i++) {
        CRPT->AES_KEY[i] = *((uint32_t *)&g_au8Buf[i * 4]);
    }

    /* Set byte count of IV */
    CRPT->AES_GCM_IVCNT[0] = ivlen;
    CRPT->AES_GCM_IVCNT[1] = 0;

    /* Set bytes count of A */
    CRPT->AES_GCM_ACNT[0] = alen;
    CRPT->AES_GCM_ACNT[1] = 0;

    /* Set bytes count of P/C (可能含 tag, 或者根本沒 tag) */
    CRPT->AES_GCM_PCNT[0] = plen;
    CRPT->AES_GCM_PCNT[1] = 0;

    // 計算對齊長度
    *plen_aligned = (plen & 0xf) ? ((plen + 16) >> 4) << 4 : plen;

    // 若 ciphertext 大小 < GCM_PBLOCK_SIZE => one-shot
    if (plen < GCM_PBLOCK_SIZE) {
        uint32_t totalSize;
        // 打包 (iv, A, ciphertext) => g_au8Buf
        AES_GCMPacker(iv, ivlen, A, alen, P, plen, g_au8Buf, &totalSize);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)buf,
                           totalSize);

        AES_Run(u32OptBasic | GCM_MODE | DMAEN | DMALAST);
    } else {
        // 分段解密
        uint32_t headerSize;
        AES_GCMPacker(iv, ivlen, A, alen, 0, 0, g_au8Buf, &headerSize);

        AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)buf,
                           headerSize);

        CRPT->AES_FBADDR = (uint32_t)&g_au8FeedBackBuf[0];

        AES_Run(u32OptBasic | GCM_MODE | FBOUT | DMAEN);

        printf("P Block size for casecade mode %d\n", GCM_PBLOCK_SIZE);
        plen_cur = plen;
        pin = P;
        pout = buf;

        while (plen_cur > 0) {
            len = plen_cur;
            if (len > GCM_PBLOCK_SIZE)
                len = GCM_PBLOCK_SIZE;
            plen_cur -= len;

            memcpy(g_au8Buf, pin, len);
            if (len & 0xf) {
                memset(&g_au8Buf[len], 0, 16 - (len & 0xf));
                len = ((len + 16) >> 4) << 4;
            }

            AES_SetDMATransfer(CRPT, 0, (uint32_t)g_au8Buf, (uint32_t)pout,
                               len);

            if (plen_cur) {
                AES_Run(u32OptBasic | GCM_MODE | FBIN | FBOUT | DMAEN | DMACC);
            } else {
                AES_Run(u32OptBasic | GCM_MODE | FBIN | FBOUT | DMAEN | DMACC |
                        DMALAST);
            }

            pin += len;
            pout += len;
        }
    }

    // [2] 修改最終回傳: 若 plen >=16 => *size = plen -16 否則 = plen
    //    前提: GCM標準Tag=16 bytes; 若沒Tag (plen<16), 亦能執行 => *size=plen
    //    由你應用層判斷是否要再做 tag 驗證
    // if (plen >= 16)
    //     *size = plen - 16;    // 表示 plaintext = (ciphertext(不含 tag))
    // else
    *size = plen; // 如果小於16，表示可能 trunc tag or no tag

    return 0;
}

void string2hex(const char *input, char *output) {
    while (*input) {
        sprintf(output, "%02X", (unsigned char)*input); // ??????????????????
        output += 2; // ??????,???????????????
        input++;     // ??????????
    }
    *output = '\0'; // ???????
}
// ???????????????
uint8_t hex_char_to_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0; // ??????,??0 (??????????????)
}

void hex2str(const char *in, char *out) {
    // 每 2 hex => 1 ASCII
    // 需要知道輸出長度 = strlen(in)/2
    size_t inLen = strlen(in);
    size_t outLen = inLen / 2;

    for (size_t i = 0; i < outLen; i++) {
        unsigned int val;
        sscanf(in + i * 2, "%02x", &val);
        out[i] = (char)val;
    }
    out[outLen] = '\0'; // 也要補上字串結尾
}

int32_t SHA256(uint32_t *pu32Addr, int32_t size, uint32_t digest[]) {
    int32_t i;
    uint32_t u32TimeOutCnt;

    /* Enable CRYPTO */
    CLK->AHBCLK |= CLK_AHBCLK_CRPTCKEN_Msk;

    /* Init SHA */
    CRPT->HMAC_CTL = (SHA_MODE_SHA256 << CRPT_HMAC_CTL_OPMODE_Pos) |
                     CRPT_HMAC_CTL_INSWAP_Msk;
    CRPT->HMAC_DMACNT = (uint32_t)size;

    /* Calculate SHA */
    while (size > 0) {
        if (size <= 4) {
            CRPT->HMAC_CTL |= CRPT_HMAC_CTL_DMALAST_Msk;
        }

        /* Trigger to start SHA processing */
        CRPT->HMAC_CTL |= CRPT_HMAC_CTL_START_Msk;

        /* Waiting for SHA data input ready */
        u32TimeOutCnt = SystemCoreClock; /* 1 second time-out */
        while ((CRPT->HMAC_STS & CRPT_HMAC_STS_DATINREQ_Msk) == 0) {
            if (--u32TimeOutCnt == 0) {
                printf("Wait for SHA data input ready time-out!\n");
                return -1;
            }
        }

        /* Input new SHA date */
        CRPT->HMAC_DATIN = *pu32Addr;
        pu32Addr++;
        size -= 4;
    }

    /* Waiting for calculation done */
    u32TimeOutCnt = SystemCoreClock; /* 1 second time-out */
    while (CRPT->HMAC_STS & CRPT_HMAC_STS_BUSY_Msk) {
        if (--u32TimeOutCnt == 0) {
            printf("Wait for SHA calculation done time-out!\n");
            return -1;
        }
    }

    /* return SHA results */
    for (i = 0; i < 8; i++)
        digest[i] = CRPT->HMAC_DGST[i];

    return 0;
}

void my_sha256(char *input, uint32_t *hash) {
    uint8_t *tmp = (uint8_t *)malloc(sizeof(uint8_t) * strlen(input));
    for (int i = 0; i < strlen(input); i++) {
        tmp[i] = (uint8_t)input[i];
    }
    SHA256((uint32_t *)(tmp), strlen(input), hash);
    ToBigEndian((uint8_t *)hash, 32);
    free(tmp);
}

int generate_keys(char *d, char *Qx, char *Qy) {
    int32_t i, j, nbits, err;
    uint32_t au32r[(KEY_LENGTH + 31) / 32];
    uint8_t *au8r;

    nbits = KEY_LENGTH;

    /* Initial TRNG */
    printf("[M2354] RNG Open ......... ");
    err = RNG_Open();
    if (err)
        printf("FAIL\n");
    else
        printf("OK\n");
    au8r = (uint8_t *)&au32r[0];
    do {
        /* Generate random number for private key */
        RNG_Random(au32r, (nbits + 31) / 32);

        for (i = 0, j = 0; i < nbits / 8; i++) {
            d[j++] = Byte2Char(au8r[i] & 0xf);
            d[j++] = Byte2Char(au8r[i] >> 4);
        }
        d[j] = 0; // NULL end

        printf("[M2354] Private key = %s\n", d);

        /* Check if the private key valid */
        if (ECC_IsPrivateKeyValid(CRPT, CURVE_P_SIZE, d)) {
            break;
        } else {
            /* Invalid key */
            printf("[M2354](generate_keys) Current private key is not valid. Need a new one.\n");
        }

    } while (1);

    /* Reset SysTick to measure time */
    if (ECC_GeneratePublicKey(CRPT, CURVE_P_SIZE, d, Qx, Qy) < 0) {
        printf("[M2354] ECC key generation failed!!\n");
        return -1;
    }

    // printf("Public Qx is %s\n", Qx);
    // printf("Public Qy is %s\n", Qy);
    return 0;
}
int sign_message(const char *msg, char *d, char *R, char *S) {
    int32_t i, j, nbits;
    uint32_t au32r[(KEY_LENGTH + 31) / 32];
    uint8_t *au8r;
    char k[70];
    au8r = (uint8_t *)&au32r[0];

    nbits = KEY_LENGTH;

    /* Generate random number k */
    // BL_Random(&rng, au8r, nbits / 8);
    RNG_Random(au32r, (nbits + 7) / 8);

    for (i = 0, j = 0; i < nbits / 8; i++) {
        k[j++] = Byte2Char(au8r[i] & 0xf);
        k[j++] = Byte2Char(au8r[i] >> 4);
    }
    k[j] = 0; // NULL End

    // printf("  k = %s\n", k);

    if (ECC_IsPrivateKeyValid(CRPT, CURVE_P_SIZE, k)) {
        /* Private key check ok */
    } else {
        /* Invalid key */
        printf("Current k is not valid\n");
        return -1;
    }

    if (ECC_GenerateSignature(CRPT, CURVE_P_SIZE, msg, d, k, R, S) < 0) {
        printf("ECC signature generation failed!!\n");
        return -1;
    }

    printf("  R  = %s\n", R);
    printf("  S  = %s\n", S);
    printf("  msg= %s\n", msg);
    return 0;
}
int verify_signature(char *Qx, char *Qy, char *R, char *S, const char *msg) {
    int32_t err;
    uint32_t time;
    printf("  msg= %s\n", msg);
    printf("  Qx = %s\n", Qx);
    printf("  Qy = %s\n", Qy);
    printf("  R  = %s\n", R);
    printf("  S  = %s\n", S);

    err = ECC_VerifySignature(CRPT, CURVE_P_SIZE, msg, Qx, Qy, R, S);

    if (err < 0) {
        printf("ECC signature verification failed!!\n");
        return -1;
    } else {
        printf("ECC digital signature verification OK.\n");
    }
    return 0;
}
int generate_secret_keys(char *d, char *Qx, char *Qy, char *k) {
    if (ECC_GenerateSecretZ(CRPT, CURVE_P_SIZE, d, Qx, Qy, k) < 0) {
        printf("ECC ECDH share key calculation fail\n");
        return -1;
    }
    printf("[M2354] Share key calculated by A = %s\n", k);
    return 0;
}
int gcm_encrypt(char *key, char *iv, char *A, char *P, uint8_t *C,
                uint32_t *plen_aligned, uint32_t *plen) {
    __ALIGNED(4)
    uint8_t g_key[32] = {0};
    __ALIGNED(4)
    uint8_t g_iv[32] = {0};
    __ALIGNED(4)
    uint8_t g_A[265] = {0};
    __ALIGNED(4)
    uint8_t g_P[256] = {0};
    // char A[] = "";
    char *myHexPlaintext = (char *)malloc(strlen(P) * 2 + 1);
    char *myHexA = (char *)malloc(strlen(A) * 2 + 1);
    string2hex(P, myHexPlaintext);
    string2hex(A, myHexA);
    printf("key: %s\n", key);
    printf("iv: %s\n", iv);
    printf("P: %s\n", P);
    printf("A: %s\n", A);
    // A = "";

    uint32_t key_len = strlen(key) / 2;
    uint32_t iv_len = strlen(iv) / 2;
    uint32_t A_len = strlen(myHexA) / 2;
    uint32_t P_len = strlen(myHexPlaintext) / 2;
    uint32_t size;
    // uint32_t plen_aligned2;

    // plen is P_len
    *plen = P_len;

    // Rule check
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("Key length error\n");
        return -1;
    }
    if (GCM_PBLOCK_SIZE & 0xf) {
        printf("GCM_PBLOCK_SIZE must be 16 bytes alignment\n");
        return -1;
    }
    if (iv_len == 0) {
        printf("IV length error\n");
        return -1;
    }
    str2bin(key, g_key, key_len);
    str2bin(iv, g_iv, iv_len);
    str2bin(myHexA, g_A, A_len);
    str2bin(myHexPlaintext, g_P, P_len);

    AES_GCMEnc(g_key, key_len, g_iv, iv_len, g_A, A_len, g_P, P_len, C, &size,
               plen_aligned);

    free(myHexA);
    free(myHexPlaintext);
    return 0;
}
int gcm_decrypt(char *key, char *iv, char *A,
                uint8_t *C, // Ciphertext
                char *P,    // 最終解出的字串 (呼叫者傳入的空間)
                uint32_t C_len) // Ciphertext 長度 (bytes)
{
    __ALIGNED(4) uint8_t g_key[32] = {0}; // 支援 16/24/32 bytes
    __ALIGNED(4) uint8_t g_iv[32] = {0};  // IV 最多 32 bytes
    __ALIGNED(4) uint8_t g_A[256] = {0};  // AAD 最多 256 bytes

    // 這些長度是以「Hex 字串長度的一半」來計算實際 bytes
    uint32_t key_len = strlen(key) / 2;
    uint32_t iv_len = strlen(iv) / 2;
    uint32_t A_len = strlen(A) / 2;

    // AES_GCMDec 回傳的兩個值：
    uint32_t size = 0;
    uint32_t plen_aligned = 0;

    // 1. 基本檢查
    if (key_len != 16 && key_len != 24 && key_len != 32) {
        printf("[gcm_decrypt] Key length error: %u\n", key_len);
        return -1;
    }
    // 確認 GCM_PBLOCK_SIZE 為 16 bytes 對齊
    if (GCM_PBLOCK_SIZE & 0xF) {
        printf("[gcm_decrypt] GCM_PBLOCK_SIZE not 16-byte aligned\n");
        return -1;
    }
    if (iv_len == 0) {
        printf("[gcm_decrypt] IV length error\n");
        return -1;
    }

    // 2. 轉換 hex string 到二進位 (key, iv, A)
    str2bin(key, g_key, key_len);
    str2bin(iv, g_iv, iv_len);
    str2bin(A, g_A, A_len);

    // 3. 清一下 g_au8Out2，避免之前殘留
    memset(g_au8Out2, 0, sizeof(g_au8Out2));

    // 4. 呼叫 AES_GCMDec 執行解密
    //    - out => g_au8Out2
    //    - size => 真正寫入的明文長度 (bytes)
    //    - plen_aligned => 可能是對齊長度
    int ret = AES_GCMDec(g_key, key_len, g_iv, iv_len, g_A, A_len, C, C_len,
                         g_au8Out2, &size, &plen_aligned);

    // 可檢查回傳值 ret，若 != 0，表示解密失敗 (依照你函式庫的定義)
    printf("[gcm_decrypt] AES_GCMDec ret = %d\n", ret);

    // 5. Debug 印出解密資訊
    printf("[gcm_decrypt] plaintext size=%u, plen_aligned=%u, C_len=%u\n", size,
           plen_aligned, C_len);

    // 若確定解出來的是文字，先手動補 '\0' 讓它成為可見字串
    // 確保 size 不超過 g_au8Out2 容量
    if (size < sizeof(g_au8Out2)) {
        g_au8Out2[size] = '\0'; // 把解密結尾補 '\0'
    } else {
        // 如果 size == 512, 也可以硬塞 g_au8Out2[511] = '\0'
        // 但代表已經達到 buffer 上限，需謹慎處理
        g_au8Out2[sizeof(g_au8Out2) - 1] = '\0';
    }

    // 6. 準備一個暫存區來放 bin2str 後的 HEX
    //    bin2str => 1 byte 變 2 HEX chars + 1 結尾字元 => 2*size + 1
    //    再預留一點空間，避免 off-by-one
    size_t tmp2Size = (size_t)(size * 2) + 4;
    char *tmp2 = (char *)malloc(tmp2Size);
    if (!tmp2) {
        printf("[gcm_decrypt] Malloc tmp2 failed\n");
        return -1;
    }
    memset(tmp2, 0, tmp2Size);

    // 7. 把解密出的二進位(plaintext) 轉成 HEX 字串放到 tmp2
    //    (假設 bin2str(g_au8Out2, size, tmp2) 不會再加結尾)
    bin2str(g_au8Out2, size, tmp2);
    // tmp2 現在大概像 "41434345..." 之類的 HEX

    // 8. 再用 hex2str 把這串 HEX 轉為你要的最終顯示格式 (ASCII？Base64？)
    //    這取決於你 hex2str() 的實際功能
    hex2str(tmp2, P);

    printf("[gcm_decrypt] P: %s\n", P);

    // 9. 釋放
    free(tmp2);

    // 如果想直接看看「解完的 plaintext (二進位)」是哪些 ASCII，這邊也可以印
    // printf("[gcm_decrypt] plaintext raw: %s\n", g_au8Out2);
    // dump_hex("plaintext raw", g_au8Out2, size);

    return 0;
}
int32_t Write_KeyStore(char key[], int key_len) {
    uint32_t au32ri[(key_len + 31) / 32], u32Meta;
    switch (key_len) {
    case 192:
        u32Meta = KS_META_192;
        break;
    case 256:
        u32Meta = KS_META_256;
        break;
    case 384:
        u32Meta = KS_META_384;
        break;
    default:
        printf("[M2354](Write_KeyStore)Unsupported key length\n");
        return -1; /*For not confusing with key ID, change from "return 1" to
                      "return -1"*/
    }

    CRPT_Hex2Reg(key, au32ri);

    return KS_Write(KS_FLASH, KS_META_ECC | u32Meta | KS_META_READABLE, au32ri);
}

int32_t Write_KeyStore_Flash_ID(char key[], int key_len, uint32_t flash_addr) {
    int32_t i32KeyId;

    i32KeyId = Write_KeyStore(key, key_len);
    if (i32KeyId < 0) {
        printf("[M2354](Write_KeyStore_Flash_ID)Fail to write key to Key "
               "Store!\n");
        return 1;
    }

    printf("[M2354](Write_KeyStore_Flash_ID)i32KeyId = %d, remain size = %d\n",
           i32KeyId, KS_GetRemainSize(KS_FLASH));

    FMC_Write(flash_addr, i32KeyId);

    return 0;
}

/* For get_Nth_nibble_char() use */
static char hex_char_tbl[] = "0123456789abcdef";
char get_Nth_nibble_char(uint32_t val32, uint32_t idx) {
    return hex_char_tbl[(val32 >> (idx * 4U)) & 0xfU];
}
void Reg2Hex(int32_t count, uint32_t volatile reg[], char output[]) {
    int32_t idx, ri;
    uint32_t i;

    output[count] = 0U;
    idx = count - 1;

    for (ri = 0; idx >= 0; ri++) {
        for (i = 0UL; (i < 8UL) && (idx >= 0); i++) {
            output[idx] = get_Nth_nibble_char(reg[ri], i);
            idx--;
        }
    }
}
int KeyStore_Read(uint32_t flash_addr, char buffer[]) {
    printf("[M2354] Entering KeyStore_Read\n");
    uint32_t au32ri[(256 + 31) / 32] = {0};
    int32_t i32KeyId = 0;
    uint32_t ui32Cnt = 0;
    /* Read the index from flash */
    i32KeyId = FMC_Read(flash_addr);
    printf("i32KeyId %i\n", i32KeyId);

    /* Get the key's word count */
    ui32Cnt = KS_GetKeyWordCnt(KS_META_ECC | KS_META_256);

    /* Read the key from key store and save it to Qxbuffer */
    if (KS_Read(KS_FLASH, i32KeyId, au32ri, ui32Cnt))
        return 1;

    Reg2Hex(66 - 2, au32ri, buffer);

    /* Print the key */
    printf("[M2354](Test_KeyStore_Read)The buffer is %s\n", buffer);

    return 0;
}
