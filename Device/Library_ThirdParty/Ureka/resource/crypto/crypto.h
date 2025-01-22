#define KEY_LENGTH 256
#define PRNG_KEY_SIZE PRNG_KEY_SIZE_256
#define CURVE_P_SIZE CURVE_KO_256

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
#define GCM_PBLOCK_SIZE 128 /* NOTE: This value must be 16 bytes alignment. This value must > size of A */
#define MAX_GCM_BUF 4096

// AES GCM

#define ENDIAN(x) ((((x) >> 24) & 0xff) | (((x) >> 8) & 0xff00) | (((x) << 8) & 0xff0000) | ((x) << 24))