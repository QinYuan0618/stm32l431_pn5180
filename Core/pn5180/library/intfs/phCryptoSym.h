/*----------------------------------------------------------------------------*/
/* Copyright 2009 - 2020, 2022, 2024 - 2025 NXP                               */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* Generic Symmetric Cryptography Component of the Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOSYM_H
#define PHCRYPTOSYM_H

#include <ph_Status.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#ifdef NXPBUILD__PH_CRYPTOSYM

/** \addtogroup phCryptoSym
 * @{
 */

/** \defgroup phCryptoSym_Defines Defines
 * \brief These are common definitions for most of the Crypto commands.
 * @{
 */

/** \defgroup phCryptoSym_Defines_KeyTypes KeyTypes
 * \brief Supported Key Types to be used in key loading functionality.
 * @{
 */
#define PH_CRYPTOSYM_KEY_TYPE_INVALID                                   0xFFFFU /**< Invalid Key */
#define PH_CRYPTOSYM_KEY_TYPE_AES128                                    0x0000U /**< AES 128 Key [16 Bytes]. */
#define PH_CRYPTOSYM_KEY_TYPE_AES192                                    0x0001U /**< AES 192 Key [24 Bytes]. */
#define PH_CRYPTOSYM_KEY_TYPE_AES256                                    0x0002U /**< AES 256 Key [32 Bytes]. */
#define PH_CRYPTOSYM_KEY_TYPE_DES                                       0x0003U /**< DES Single Key [8 Bytes]. This is basically the 56-Bit DES key. */
#define PH_CRYPTOSYM_KEY_TYPE_2K3DES                                    0x0004U /**< 2 Key Triple Des [16 Bytes]. This is basically the 112-Bit DES key. */
#define PH_CRYPTOSYM_KEY_TYPE_3K3DES                                    0x0005U /**< 3 Key Triple Des [24 Bytes]. This is basically the 168-Bit DES key. */
/**
 * end of group phCryptoSym_Defines_KeyTypes
 * @}
 */

/** \defgroup phCryptoSym_Defines_KeySize KeySize
 * \brief Supported KeySizes for AES and DES algorithms.
 * @{
 */

/** \defgroup phCryptoSym_Defines_KeySize_DES DES
 * \brief Supported KeySizes DES algorithms.
 * @{
 */
#define PH_CRYPTOSYM_DES_BLOCK_SIZE                                         8U  /**< Block size in DES algorithm */
#define PH_CRYPTOSYM_DES_KEY_SIZE                                           8U  /**< Key size in DES algorithm for 56 bit key */
#define PH_CRYPTOSYM_2K3DES_KEY_SIZE                                        16U /**< Key size in AES algorithm for 112 bit key */
#define PH_CRYPTOSYM_3K3DES_KEY_SIZE                                        24U /**< Key size in AES algorithm for 168 bit key */
/**
 * end of group phCryptoSym_Defines_KeySize_DES
 * @}
 */

/** \defgroup phCryptoSym_Defines_KeySize_AES AES
 * \brief Supported KeySizes AES algorithms.
 * @{
 */
#define PH_CRYPTOSYM_AES_BLOCK_SIZE                                         16U /**< Block size in AES algorithm */
#define PH_CRYPTOSYM_AES128_KEY_SIZE                                        16U /**< Key size in AES algorithm for 128 bit key */
#define PH_CRYPTOSYM_AES192_KEY_SIZE                                        24U /**< Key size in AES algorithm for 192 bit key */
#define PH_CRYPTOSYM_AES256_KEY_SIZE                                        32U /**< Key size in AES algorithm for 256 bit key */

#define PH_CRYPTOSYM_AES_CCM_ADD_DATA_SIZE                              65280U  /**< Maximum Additional Data Size for AES-CCM or AES-CCM* cipher mode operation. */

/**
 * end of group phCryptoSym_Defines_KeySize_AES
 * @}
 */

/**
 * end of group phCryptoSym_Defines_KeySize
 * @}
 */

/** \defgroup phCryptoSym_Defines_CipherModes Cipher Modes
 * \brief Supported Cipher Modes
 * @{
 */
#define PH_CRYPTOSYM_CIPHER_MODE_ECB                                    0x00U   /**< Electronic Code Book (ECB) Cipher Mode. */
#define PH_CRYPTOSYM_CIPHER_MODE_CBC                                    0x01U   /**< Cipher Block Chaining (CBC) Cipher Mode. */
#define PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4                                0x02U   /**< Cipher Block Chaining (CBC) Cipher Mode for
                                                                                 *   D40 Secure Messaging.
                                                                                 */

#define PH_CRYPTOSYM_CIPHER_MODE_CCM                                    0x04U   /**< Counter with Cipher Block Chaining-Message Authentication Code (CCM) Cipher Mode.
                                                                                 *   Also known as Counter with CBC-MAC
                                                                                 */
#define PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR                               0x05U   /**< Counter with Cipher Block Chaining-Message Authentication Code (CCM*) Cipher Mode.
                                                                                 *   Supports MAC lengths down to 0 (which disables authentication and becomes encryption-only)
                                                                                 *   Also known as Counter with CBC-MAC
                                                                                 */

/**
 * end of group phCryptoSym_Defines_CipherModes
 * @}
 */

/** \defgroup phCryptoSym_Defines_MacModes MAC Modes
 * \brief Supported Mac Modes.
 * @{
 */
#define PH_CRYPTOSYM_MAC_MODE_CMAC                                      0x00U   /**< Cipher-Based Message Authentication Code (CMAC) Mode. */
#define PH_CRYPTOSYM_MAC_MODE_CBCMAC                                    0x01U   /**< Cipher Block Chaining Message Authentication Code
                                                                                 *   (CBCMAC) MAC Mode.
                                                                                 */

/**
 * end of group phCryptoSym_Defines_MacModes
 * @}
 */

/** \defgroup phCryptoSym_Defines_DivTypes Diversification Types
 * \brief Supported Diversification Types.
 * @{
 */
#define PH_CRYPTOSYM_DIV_MODE_MASK                                      0x00FFU /**< Bit-mask for diversification Mode. */
#define PH_CRYPTOSYM_DIV_MODE_DESFIRE                                   0x0000U /**< DESFire Key Diversification. */
#define PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS                               0x0001U /**< MIFARE Plus Key Diversification. */
#define PH_CRYPTOSYM_DIV_MODE_MIFARE_ULTRALIGHT                         0x0002U /**< MIFARE Ultralight Key Diversification. */
#define PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL                             0x0000U /**< Option for 2K3DES full-key diversification
                                                                                 * (To use along with only with \ref PH_CRYPTOSYM_DIV_MODE_DESFIRE
                                                                                 * "DESFire Key Diversification").
                                                                                 */
#define PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF                             0x8000U /**< Option for 2K3DES half-key diversification
                                                                                 * (To use along with only with \ref PH_CRYPTOSYM_DIV_MODE_DESFIRE
                                                                                 * "DESFire Key Diversification").
                                                                                 */
/**
 * end of group phCryptoSym_Defines_DivTypes
 * @}
 */

/** \defgroup phCryptoSym_Defines_PaddModes Padding Modes
 * \brief Supported Padding Modes.
 * @{
 */
#define PH_CRYPTOSYM_PADDING_MODE_1                                         00U /**< Pad with all zeros */
#define PH_CRYPTOSYM_PADDING_MODE_2                                         01U /**< Pad with a one followed by all zeros */
/**
 * end of group phCryptoSym_Defines_PaddModes
 * @}
 */

/** \defgroup phCryptoSym_Defines_Config Configuration
 * \brief CryptoSym Layer Configuration types.
 * @{
 */

/** \defgroup phCryptoSym_Defines_ConfigTypes Config Types
 * \brief CryptoSym Layer Configuration types.
 * @{
 */
#define PH_CRYPTOSYM_CONFIG_KEY_TYPE                                    0x0000U /**< Key Type. Read-only. Possible Values are:
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_INVALID "Invalid Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES128 "AES 128Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES192 "AES 192Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES256 "AES 256Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_DES "DES Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_2K3DES "TripleDES - 2Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_3K3DES "TripleDES - 3Key"
                                                                                 */
#define PH_CRYPTOSYM_CONFIG_KEY_SIZE                                    0x0001U /**< Key Size of currently loaded key. Read-only.  */
#define PH_CRYPTOSYM_CONFIG_BLOCK_SIZE                                  0x0002U /**< Block Size of currently loaded key. Read-only. */
#define PH_CRYPTOSYM_CONFIG_KEEP_IV                                     0x0003U /**< Keep init vector.
                                                                                 *      - Either \ref PH_CRYPTOSYM_VALUE_KEEP_IV_OFF "OFF" or
                                                                                 *        \ref PH_CRYPTOSYM_VALUE_KEEP_IV_ON "ON".
                                                                                 *      - This flag has to be used in combination with the option
                                                                                 *        flag in the \ref phCryptoSym_Encrypt "Encrypt" /
                                                                                 *        \ref phCryptoSym_Decrypt "Decrypt" /
                                                                                 *        \ref phCryptoSym_CalculateMac "Calculate MAC" interfaces.
                                                                                 *      - If either the option in the function or this flag is set, the
                                                                                 *        IV will be updated before returning of the function. R/W access
                                                                                 *        possible.
                                                                                 */

#define PH_CRYPTOSYM_CONFIG_ADDITIONAL_INFO                             0x0006U /**<  Additional information to be provided like diversified key length. */

#define PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH                              0x0007U /**<  Authentication Tag. To be used when CCM or CCM* cipher modes are used.
                                                                                 *    Supported values are,
                                                                                 *      - 4, 6, 8, 10, 12, 14 or 16 in case of CCM
                                                                                 *      - 0, 4, 6, 8, 10, 12, 14 or 16 in case of CCM*
                                                                                 */

/**
 * end of group phCryptoSym_Defines_ConfigTypes
 * @}
 */

/** \defgroup phCryptoSym_Defines_KeepIV Keep IV
 * \brief Supported IV Updated Behavior Modes.
 * @{
 */
#define PH_CRYPTOSYM_VALUE_KEEP_IV_OFF                                  0x0000U /**< Switch off Keep-IV behavior. */
#define PH_CRYPTOSYM_VALUE_KEEP_IV_ON                                   0x0001U /**< Switch on Keep-IV behavior. */
/**
 * end of group phCryptoSym_Defines_KeepIV
 * @}
 */

/** \defgroup phCryptoSym_Defines_Tag Authentication Tag
 * \brief Supported Option to be used for below mentioned interfaces for CCM and CCM* cipher modes.
 *  - \ref phCryptoSym_Encrypt "Encryption"
 *  - \ref phCryptoSym_Decrypt "Decryption"
 * @{
 */
#define PH_CRYPTOSYM_AUTH_TAG_OFF                                       0x0000U /**< Authentication tag information is not part of Output buffer
                                                                                 *   for \ref phCryptoSym_Encrypt "Encrypt" and not part of input
                                                                                 *   buffer for \ref phCryptoSym_Decrypt "Decrypt" operations.
                                                                                 */
#define PH_CRYPTOSYM_AUTH_TAG_ON                                        0x0080U /**< Authentication tag information is part of Output buffer
                                                                                 *   for \ref phCryptoSym_Encrypt "Encrypt" and part of input
                                                                                 *   buffer for \ref phCryptoSym_Decrypt "Decrypt" operations.
                                                                                 */
/**
 * end of group phCryptoSym_Defines_Tag
 * @}
 */

/**
 * end of group phCryptoSym_Defines_Config
 * @}
 */

/**
 * end of group phCryptoSym_Defines
 * @}
 */

/**
 * end of group phCryptoSym
 * @}
 */
#endif /* NXPBUILD__PH_CRYPTOSYM */

#ifdef NXPBUILD__PH_CRYPTOSYM_SW

#define PH_CRYPTOSYM_SW_ID                                              0x01U   /**< ID for Software crypto component. */

/** \addtogroup phCryptoSym_Sw Component : Software
 * \brief Software implementation of the Symmetric Cryptography interface.
 *
 * This implementation was designed to optimize the footprint of crypto libraries used in embedded systems.
 * The following standards are implemented:
 * - Federal Information Processing Standards Publication 197: AES 128, 192 and 256
 * - Federal Information Processing Standards Publication 46-3: DES
 * - NIST Special Publication 800-67 Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher
 * - NIST Special Publication 800-38B: CMAC
 * - NIST Special Publication 800-38A: CBC and ECB mode
 * - NIST Special Publication 800-38A: CMC-MAC
 *
 * Hints for compiling the library:
 * - Carefully read the section on compile switches in order to find the optimum balance between speed and memory utilization.
 * - Using the appropriate compile switches either AES or DES can be removed from the built completely.
 *
 * Architecture of the \ref phCryptoSym_Sw "Software" Component:
 * - The DES algorithm is implemented in the \ref phCryptoSym_Sw_DES "DES Core" block
 * - The AES algorithm is implemented in the \ref phCryptoSym_Sw_AES "AES Core" block
 * - The phCryptoSym_Int block implements generic encrypt and decrypt functions. This offers the possibility to implement modes
 *   of operations without consideration of currently selected key type or key size.
 * - The phCryptoSym_Int block in addition implements helper functions for CMAC calculations.
 * @{
 */

/** \defgroup phCryptoSym_Sw_CompileSwitch Compile Switch
 * \brief Compile switches used to find the optimum trade-off between performance, memory footprint and supported features.
 * @{
 */

/**
 * \brief Enables DES support.
 *
 * Defines that the DES algorithm is supported. The defines for general DES capabilities like block sizes etc. are not affected
 * as they do not add to the memory footprint.
 */
#define PH_CRYPTOSYM_SW_DES

/**
 * \brief Enables AES support.
 *
 * Defines that the AES algorithm is supported. The defines for general AES capabilities like block sizes etc. are not affected
 * as they do not add to the memory footprint.
 */
#define PH_CRYPTOSYM_SW_AES

/**
 * \brief Enables online key scheduling.
 *
 * This define enables for both AES and DES the online key scheduling. This means, that the round keys are not pre-calculated
 * at key loading, but they are always calculated when a new block is going to be encrypted or decrypted.
 *
 * The following advantages come out of enabling online key scheduling:
 * - The pKey entry of the private data param structure decreases significantly from 384(DES enabled)/256(DES disabled) to 32 bytes.
 * - As the private data structure has to be created for each instance, the above mentioned savings count for each instance.
 * - Key loading is very fast (as there is almost nothing performed any more.
 * - On 8051 the keys can be located in fast RAM which counters some of the performance decrease compared to disabling that feature.
 *
 * The following disadvantages come out of enabling online key scheduling:
 * - Encryption gets slower as in addition to the ciphering also the round key generation has to be performed.
 * - For decryption in AES the situation is even worse, as the key scheduling is executed twice for each decryption.
 * - On small platforms like 8051 big key buffers can never reside in fast RAM as they exceed the memory size of data and data.
 *
 * On 8051 platforms in combination with the PH_CRYPTOSYM_SW_USE_8051_DATA_STORAGE enabling online key scheduling even gives better results
 * on execution time if only 1 or 2 blocks are encrypted with a given key. In case of keys are used longer (which is most likely the standard case),
 * it is faster to disable that feature.
 * Also note, that e.g. for a MIFARE Plus (R) instance of the library, two crypto instances are required, and as a consequence online key
 * scheduling can save 704(DES enabled)/(DES disabled)448 bytes of RAM.
 */
#define PH_CRYPTOSYM_SW_ONLINE_KEYSCHEDULING

/**
 * \brief Enables online CMAC SubKey calculation.
 *
 * This define enables for both AES and DES the online CMAC SubKey calculation. This means, that the CMAC SubKeys are not stored in the
 * context of the individual instance of the crypto lib, but they are newly calculated for each MAC.
 *
 * The following advantages come out of enabling online CMAC SubKey calculation:
 * - 32 bytes of RAM can be saved in the private DataParams (so they are saved on each instance of the crypto library).
 *
 * The following disadvantages come out of online CMAC SubKey calculation:
 * - Each CMAC calculation needs 1 additional encryption and 2 additional shift operations, so the execution speed decreases.
 */
#define PH_CRYPTOSYM_SW_ONLINE_CMAC_SUBKEY_CALCULATION

/**
 * \brief Enables ROM optimizations in the AES algorithm.
 *
 * This define removes some of the lookup tables in the AES implementation to save ROM space.
 *
 * The following advantages come out of enabling ROM optimizations:
 * - 3 lookup tables of 256 bytes can be saved (some additional code is needed, so in fact only ~600 bytes are saved).
 *
 * The following disadvantages come out of enabling ROM optimizations:
 * - The MixColumn and MixColumnInv implementation of the AES are getting slower.
 */
#define PH_CRYPTOSYM_SW_ROM_OPTIMIZATION

/**
 * \brief Enables 8051 data storage specifier.
 *
 * This define allows to specify any value for #PH_CRYTOSYM_SW_FAST_RAM. It takes care, that the buffers are recopied correctly,
 * and that most of the time consuming calculations are done on this fast memory. In case of #PH_CRYPTOSYM_SW_ONLINE_KEYSCHEDULING
 * is set, even the key scheduling can be performed on this fast memory.
 */
 /*
 #define PH_CRYPTOSYM_SW_USE_8051_DATA_STORAGE
 */

#ifdef PH_CRYPTOSYM_SW_USE_8051_DATA_STORAGE
#define PH_CRYTOSYM_SW_FAST_RAM data                                            /**< Fast RAM specifier, only useful in combination with
                                                                                 *   #PH_CRYPTOSYM_SW_USE_8051_DATA_STORAGE
                                                                                 */
#define PH_CRYPTOSYM_SW_CONST_ROM                                               /**< Constant code specifier, only useful in combination
                                                                                 *   with #PH_CRYPTOSYM_SW_USE_8051_DATA_STORAGE
                                                                                 */
#define PH_CRYPTOSYM_CONST_ROM  PH_CRYPTOSYM_SW_CONST_ROM
#else
#define PH_CRYTOSYM_SW_FAST_RAM                                                 /**< Fast RAM specifier - not set per default */
#define PH_CRYPTOSYM_SW_CONST_ROM                                               /**< ROM specifier - not set per default */
#define PH_CRYPTOSYM_CONST_ROM  PH_CRYPTOSYM_SW_CONST_ROM
#endif

#ifndef PH_CRYPTOSYM_SW_AES
#ifdef PH_CRYPTOSYM_SW_DES
#ifndef PH_CRYPTOSYM_MAX_BLOCK_SIZE
#define PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE              PH_CRYPTOSYM_DES_BLOCK_SIZE /**< Maximum Block Size of the currently supported ciphers*/
#endif /* PH_CRYPTOSYM_MAX_BLOCK_SIZE */
#else
#error "No symmetric cipher available"
#endif /* PH_CRYPTOSYM_SW_DES */
#else
#define PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE              PH_CRYPTOSYM_AES_BLOCK_SIZE /**< Maximum Block Size of the currently supported ciphers*/

#ifndef PH_CRYPTOSYM_MAX_BLOCK_SIZE
#define PH_CRYPTOSYM_MAX_BLOCK_SIZE                 PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE /**< Maximum Block Size of the currently supported ciphers*/
#endif /* PH_CRYPTOSYM_MAX_BLOCK_SIZE */
#endif /* PH_CRYPTOSYM_SW_AES */

/* Key buffer size is calculated as follows: */
/* DES offline key scheduling: 3 #numKeys * 16 #numRounds * 8 #KeySize = 384 Bytes */
/* DES online key scheduling: 3 #numKeys * 2 #temporaryKey+originalKey * 8 #KeySize + 8 #intermediate result = 56 Bytes  */
/* AES offline key scheduling: (13u + 2U) (#numRounds + #original) * 16 #KeySize = 240 Bytes */
/* AES online key scheduling: (1u + 1U) (#temporary + #original) * 32 #KeySize = 64 Bytes */

#ifdef PH_CRYPTOSYM_SW_ONLINE_KEYSCHEDULING
#define PH_CRYPTOSYM_SW_KEY_BUFFER_SIZE                                 32U     /**< Maximum Key buffer Size of the currently supported ciphers. */
#else
#ifdef PH_CRYPTOSYM_SW_DES
#define PH_CRYPTOSYM_SW_KEY_BUFFER_SIZE                                 384U    /**< Maximum Key buffer Size of the currently supported ciphers. */
#else
#define PH_CRYPTOSYM_SW_KEY_BUFFER_SIZE                                 240U    /**< Maximum Key buffer Size of the currently supported ciphers. */
#endif /* PH_CRYPTOSYM_SW_DES */
#endif /* PH_CRYPTOSYM_SW_ONLINE_KEYSCHEDULING */

 /**
 * end of group phCryptoSym_Sw_CompileSwitch
 * @}
 */

 /** \brief Data structure for Symmetric Crypto Software layer implementation. */
typedef struct
{
    uint16_t wId;                                                               /**< Layer ID for this component, NEVER MODIFY! */
    void * pKeyStoreDataParams;                                                 /**< Pointer to Key Store object - can be NULL. */
#ifndef NXPBUILD__PH_CRYPTOSYM_LRP
    uint8_t pKey[PH_CRYPTOSYM_SW_KEY_BUFFER_SIZE];                              /**< Internal key storage array */
#endif /* NXPBUILD__PH_CRYPTOSYM_LRP */
    uint8_t pIV[PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE];                                /**< Internal IV storage array */
#ifndef PH_CRYPTOSYM_SW_ONLINE_CMAC_SUBKEY_CALCULATION
    uint8_t pCMACSubKey1[PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE];                       /**< Internal Key1 storage for MAC calculation. */
    uint8_t pCMACSubKey2[PH_CRYPTOSYM_SW_MAX_BLOCK_SIZE];                       /**< Internal Key2 storage for MAC calculation. */
    uint8_t bCMACSubKeysInitialized;                                            /**< Indicates whether the SubKeys have been calculated. */
#endif /* PH_CRYPTOSYM_SW_ONLINE_CMAC_SUBKEY_CALCULATION */
    uint16_t wKeyType;                                                          /**< Key Type. */
    uint16_t wKeepIV;                                                           /**< Indicates if the init vector of a previous crypto operation shall be
                                                                                 * used for the next operation.
                                                                                 */
    uint16_t wAddInfo;                                                          /**< Additional information like diversified key length, etc. */
} phCryptoSym_Sw_DataParams_t;

/**
 * \brief Initialize the CryptoSym with Software as sub-component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS
 *          - If the input size do not match the DataParams size of this component.
 *          - If any of the DataParams are null.
 *
 */
phStatus_t phCryptoSym_Sw_Init(
        phCryptoSym_Sw_DataParams_t * pDataParams,                              /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                             /**< [In] Specifies the size of the data parameter structure. */
        void * pKeyStoreDataParams                                              /**< [In] Pointer to a key store structure (can be null). */
    );

/**
 * end of group phCryptoSym_Sw
 * @}
 */
#endif /* NXPBUILD__PH_CRYPTOSYM_SW */

#ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS

#include <mbedtls_config_sw.h>

#define PH_CRYPTOSYM_MBEDTLS_ID                                         0x03U    /**< ID for mBedTLS crypto component. */

#ifndef PH_CRYPTOSYM_DES
#if defined(MBEDTLS_DES_C) || defined(MBEDTLS_DES_ALT)
/**
 * \brief Enables DES support.
 *
 * Defines that the DES algorithm is supported. The defines for general DES capabilities like block sizes etc. are not affected
 * as they do not add to the memory footprint.
 */
#define PH_CRYPTOSYM_DES
#include <mbedtls/des.h>
#endif /* MBEDTLS_DES_C */
#endif /* PH_CRYPTOSYM_DES */

#ifndef PH_CRYPTOSYM_AES
#if defined(MBEDTLS_AES_C) || defined(MBEDTLS_AES_ALT) || defined(MBEDTLS_CCM_C)
/**
 * \brief Enables AES support.
 *
 * Defines that the AES algorithm is supported. The defines for general AES capabilities like block sizes etc. are not affected
 * as they do not add to the memory footprint.
 */
#define PH_CRYPTOSYM_AES
#include <mbedtls/aes.h>
#endif /* defined(MBEDTLS_AES_C) || defined(MBEDTLS_AES_ALT) || defined(MBEDTLS_CCM_C) */

#ifdef MBEDTLS_CCM_C
#include <mbedtls/ccm.h>
#endif /* MBEDTLS_CCM_C */

#endif /* PH_CRYPTOSYM_AES */

#if !defined(PH_CRYPTOSYM_AES)
#if defined(PH_CRYPTOSYM_DES)
#ifndef PH_CRYPTOSYM_MAX_BLOCK_SIZE
#define PH_CRYPTOSYM_MAX_BLOCK_SIZE                 PH_CRYPTOSYM_DES_BLOCK_SIZE /**< Maximum Block Size of the currently supported ciphers*/
#endif /* PH_CRYPTOSYM_MAX_BLOCK_SIZE */
#else
#error "No symmetric cipher available"
#endif /* PH_CRYPTOSYM_DES */
#else
#ifndef PH_CRYPTOSYM_MAX_BLOCK_SIZE
#define PH_CRYPTOSYM_MAX_BLOCK_SIZE                 PH_CRYPTOSYM_AES_BLOCK_SIZE /**< Maximum Block Size of the currently supported ciphers*/
#endif /* PH_CRYPTOSYM_MAX_BLOCK_SIZE */
#endif /* PH_CRYPTOSYM_AES */

/** \addtogroup phCryptoSym_mBedTLS Component : mBedTLS
 * \brief Initialize the CryptoSym with mBedTLS as sub-component.
 *
 * \note:
 *      - LRP (Leakage Resilient Primitive) feature is not supported.
 *      - CMAC implementation of mBedTLS library is not utilized due to below mentioned reason(s)
 *          - When using \ref phalMfdfEVx "MIFARE DESFire EVx" AL component, CMAC computation excluding the first call requires
 *            IV of the last subsequent calls. Here the IV is only zero for the first call and non zero for the rest of the
 *            calls. This behavior is required for EV1 Secure messaging of MIFARE DESFire product.
 *          - Its not possible to update the IV for intermediate / final calls provide by mBedTLS.
 *          - To over come this, CMAC is implemented directly in this component using cipher interfaces of mBedTLS.
 *          - The above limitation is valid only for \ref phCryptoSym_CalculateMac "CalculateMac" interface.
 *      - CMAC implementation of mBedTLS library is not utilized due to below mentioned reason(s)
 *          - CMAC implementation provided by mBedTLS library do not support 3DES-2Key key diversification.
 *          - Based on <a href="https://www.nxp.com/docs/en/application-note/AN10922.pdf">AN10922</a> CryptoSym should
 *            support diversification of 3DES-2Key but mBedTLS CMAC library do not support this key type.
 *          - To over come this, CMAC is implemented directly in this component using cipher interfaces of mBedTLS.
 *          - The above limitation is valid only for below mentioned interfaces.
 *              - \ref phCryptoSym_DiversifyKey "Diversify the key available in KeyStore"
 *              - \ref phCryptoSym_DiversifyDirectKey "Diversify the provided key as input"
 *      - Additional Data for \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" or \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*" cipher mode
 *        can be set using \ref phCryptoSym_LoadAdditionalData "Load Additional Data" interface.
 *      - Tag Length can be configured using \ref phCryptoSym_GetConfig "GetConfig" with \ref PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "Tag Length"
 *        as configuration identifier.
 *      - Tag information can be configured using \ref phCryptoSym_SetAuthenticationTag "Set Authentication Tag" for \ref phCryptoSym_Decrypt
 *        "Decryption" operation. Refer \ref phCryptoSym_Decrypt "Decryption" interface for more information.
 *      - Tag information can be retrieved using \ref phCryptoSym_GetAuthenticationTag "Get Authentication Tag" for \ref phCryptoSym_Encrypt
 *        "Encryption" operation. Refer \ref phCryptoSym_Encrypt "Encryption" interface for more details.
 *      - Refer \ref phCryptoSym_Encrypt "Encryption" interface for more details on CCM output behavior
 *      - Refer \ref phCryptoSym_Decrypt "Decryption" interface for more details on CCM Input behavior
 * @{
 */

typedef struct
{
#ifdef PH_CRYPTOSYM_DES
#ifndef MBEDTLS_DES_ALT
    mbedtls_des_context stDES;
#endif /* MBEDTLS_DES_ALT */

    mbedtls_des3_context st3DES;
#endif /* PH_CRYPTOSYM_DES */

#ifdef PH_CRYPTOSYM_AES
    mbedtls_aes_context stAES;
#endif /* PH_CRYPTOSYM_AES */

#ifdef MBEDTLS_CCM_C
    mbedtls_ccm_context stAES_CCM;
#endif /* MBEDTLS_CCM_C */

}phCryptoSym_mBedTLS_Context;

 /** \brief Data structure for Symmetric Crypto mBedTLS layer implementation. */
typedef struct
{
    uint16_t wId;                                                               /**< Layer ID for this component, NEVER MODIFY! */
    void * pKeyStoreDataParams;                                                 /**< Pointer to Key Store object - can be NULL. */
    void * pCtx_Crypto;                                                         /**< Pointer to underlying Symmetric Crypto context for AES or DES operations. */
    uint8_t aKey[PH_CRYPTOSYM_AES256_KEY_SIZE];                                 /**< Internal key storage array. */
    uint8_t aIV[PH_CRYPTOSYM_MAX_BLOCK_SIZE];                                   /**< Internal IV storage array. IV in case of CBC and Nonce in case of CCM or CCM* cipher mode. */
    uint8_t bIV_Len;                                                            /**< Length of bytes available in \b aIV buffer. This is required for CCM or CCM* Cipher mode. */
    uint8_t * pAddData;                                                         /**< Internal Additional Data storage array. This is required for CCM or CCM* Cipher mode. */
    uint16_t wAddData_Len;                                                      /**< Length of bytes available in \b pAddData buffer. This is required for CCM or CCM* Cipher mode. */
    uint16_t wAddData_Size;                                                     /**< Maximum size allocated for \b pAddData buffer. This is required for CCM or CCM* Cipher mode. */
    uint8_t aTag[PH_CRYPTOSYM_AES128_KEY_SIZE];                                 /**< To store Authentication Tag information that will be generated during Encryption or used while Decryption.
                                                                                 *   This is required for CCM or CCM* Cipher mode.
                                                                                 */
    uint8_t bTagLen;                                                            /**< Authentication Tag. To be used when CCM or CCM* cipher modes are used.
                                                                                *    Supported values are,
                                                                                *      - 4, 6, 8, 10, 12, 14 or 16 in case of CCM
                                                                                *      - 0, 4, 6, 8, 10, 12, 14 or 16 in case of CCM*
                                                                                */
    int32_t dwErrorCode;                                                        /**< Error code returned by mbedTLS layer. */
    uint16_t wKeyType;                                                          /**< Specific Key Type.  */
    uint16_t wKeyNo;                                                            /**< Internal Key Storage number. Will be utilized for Alternate implementation. */
    uint16_t wKeepIV;                                                           /**< Indicates if the init vector of a previous crypto operation shall be
                                                                                 *   used for the next operation.
                                                                                 */
    uint16_t wKey_Bit;                                                          /**< Length of Key in terms of Bits. */
    uint16_t wAddInfo;                                                          /**< Additional information like diversified key length, etc. */
    uint8_t bIsDirectKey;                                                       /**< Specify if the Key to be used is directly loaded or taken from KeyStore.
                                                                                 *      - #PH_ON: If the Key is loaded directly.
                                                                                 *      - #PH_OFF: If the Key is loaded from KeyStore.
                                                                                 */
} phCryptoSym_mBedTLS_DataParams_t;

/**
 * \brief Initialize the CryptoSym with mBedTLS as sub-component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS
 *          - If the input size do not match the DataParams size of this component.
 *          - If any of the DataParams are null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *          - If \b wAddData_Size > 0 and pAddData_Buffer is NULL.
 *          - If \b wAddData_Size > Maximum size (65280).
 */
phStatus_t phCryptoSym_mBedTLS_Init(
        phCryptoSym_mBedTLS_DataParams_t * pDataParams,                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                             /**< [In] Specifies the size of the data parameter structure. */
        void * pKeyStoreDataParams,                                             /**< [In] Pointer to a key store structure (can be null).*/
        uint8_t * pAddData_Buffer,                                              /**< [In] Pointer to Additional Data buffer (can be null).
                                                                                 *        This is used for AES-CCM or AES-CCM* Cipher mode
                                                                                 */
        uint16_t wAddData_Size                                                  /**< [In] Size allocated for \b pAddData_Buffer.
                                                                                 *          - Non zero if null is not provided for \b pAddData_Buffer.
                                                                                 *            Maximum size should be less than 2^16 - 2^8 = 65280.
                                                                                 *          - Zero if null is provided for \b pAddData_Buffer
                                                                                 */
    );

/**
 * \brief De-Initialize the CryptoSym with mBedTLS as sub-component.
 * \note Its must to call this interface to Un-initialize any used global context from other libraries.
 * If not called, there might be unusual behavior for the next executions.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_mBedTLS_DeInit(
    phCryptoSym_mBedTLS_DataParams_t * pDataParams                              /**< [In] Pointer to this layer's parameter structure. */
);

/**
* end of group phCryptoSym_mBedTLS
* @}
*/
#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */

#ifdef NXPBUILD__PH_CRYPTOSYM

/** \addtogroup phCryptoSym CryptoSym
 *
 * \brief This is only a wrapper layer to abstract the different CryptoSym implementations.
 * With this wrapper it is possible to support more than one CryptoSym implementation
 * in parallel, by adapting this wrapper.
 *
 * Important hints for users of this component:
 * - Before use of any function, the dedicated crypto implementation has to be initialized using either of the interfaces mentioned below.
 *      - \ref phCryptoSym_Sw_Init "Software Initialization"
 *      - \ref phCryptoSym_mBedTLS_Init "mBedTLS Initialization"
 * - Functions using a key store ( \ref phCryptoSym_LoadKey "Load Key" and \ref phCryptoSym_DiversifyKey "Diversify Key" ) are only available if
 *   a key store has been passed during component initialization.
 * - Before any cipher operation or MAC operation ( \ref phCryptoSym_Encrypt "Encrypt", \ref phCryptoSym_Decrypt "Decrypt", \ref phCryptoSym_CalculateMac
 *   "CalculateMAC" ) can be used, a key has to be loaded using either \ref phCryptoSym_LoadKey "LoadKey" or \ref phCryptoSym_LoadKeyDirect "LoadKeyDirect".
 * - Before any cipher operation or MAC operation ( \ref phCryptoSym_Encrypt "Encrypt", \ref phCryptoSym_Decrypt "Decrypt", \ref phCryptoSym_CalculateMac
 *   "CalculateMAC" ) can be used, an appropriate IV has to be loaded by calling \ref phCryptoSym_LoadIv "LoadIv". Prior to this Key should be loaded.
 * - Using \ref phCryptoSym_GetConfig "GetConfig", the block sizes, key lengths and Diversified key length for the currently loaded / diversified key can
 *   be retrieved.
 * - Cipher mode \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" or \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*" is supported in mBedTLS component only or
 *   based on DUT feature support.
 *  - Before any cipher operation ( \ref phCryptoSym_Encrypt "Encrypt" and \ref phCryptoSym_Decrypt "Decrypt") with
 *    \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" or \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*" as cipher mode,
 *      - Nonce has to be loaded by calling \ref phCryptoSym_LoadNonce "Load Nonce". Prior to this Key should be loaded.
 *      - Additional Data can be set using \ref phCryptoSym_LoadAdditionalData "Load Additional Data" interface. This is optional
 *      - Tag Length can be configured using \ref phCryptoSym_GetConfig "GetConfig" with \ref PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "Tag Length"
 *        as configuration identifier.
 *      - Tag information can be configured using \ref phCryptoSym_SetAuthenticationTag "Set Authentication Tag" for \ref phCryptoSym_Decrypt
 *        "Decryption" operation. Refer \ref phCryptoSym_Decrypt "Decryption" interface for more information.
 *      - Tag information can be retrieved using \ref phCryptoSym_GetAuthenticationTag "Get Authentication Tag" for \ref phCryptoSym_Encrypt
 *        "Encryption" operation. Refer \ref phCryptoSym_Encrypt "Encryption" interface for more details.
 *
 * \note:
 *      The following are applicable when CryptoSym is initialized to use \ref phCryptoSym_mBedTLS "mBedTLS" as underlying layer.
 *      - LRP (Leakage Resilient Primitive) feature is not supported.
 *      - CMAC implementation of mBedTLS library is not utilized due to below mentioned reason(s)
 *          - When using \ref phalMfdfEVx "MIFARE DESFire" AL component, CMAC computation leaving the first call requires
 *            IV of the last subsequent calls. Here the IV is only zero for the first call and non zero for the rest of the
 *            calls. This behavior is required for EV1 Secure messaging of MIFARE DESFire product.
 *          - Its not possible to update the IV for intermediate / final calls provide by mBedTLS.
 *          - To over come this, CMAC is implemented directly in this component using cipher interfaces of mBedTLS.
 *          - The above limitation is valid only for \ref phCryptoSym_CalculateMac "CalculateMac" interface.
 *      - CMAC implementation of mBedTLS library is not utilized due to below mentioned reason(s)
 *          - CMAC implementation provided by mBedTLS library do not support 3DES-2Key key diversification.
 *          - Based on <a href="https://www.nxp.com/docs/en/application-note/AN10922.pdf"><b>AN10922</b></a> CryptoSym should
 *            support diversification of 3DES-2Key but mBedTLS CMAC library do not support this key type.
 *          - To over come this, CMAC is implemented directly in this component using cipher interfaces of mBedTLS.
 *          - The above limitation is valid only for below mentioned interfaces.
 *              - \ref phCryptoSym_DiversifyKey "Diversify the key available in KeyStore"
 *              - \ref phCryptoSym_DiversifyDirectKey "Diversify the provided key as input"
 * @{
 */

/**
 * \brief Invalidate the currently loaded key.
 * Resets the key, the IV, the keep IV flag and the key Type.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_InvalidateKey(
        void * pDataParams                                                      /**< [In] Pointer to this layer's parameter structure */
    );

/**
 * \brief Perform Encryption with one of the supported crypto modes
 *
 * The \b wOption word specifies the operation mode to use, Authentication Tag information for Encryption and the update behavior of the IV.
 * All modes of operation are coded in the LSB, the flags in the MSB.
 *  - The following Cipher modes are supported:
 *      - #PH_CRYPTOSYM_CIPHER_MODE_ECB "Electronic Code Book"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CBC "Cipher Block Chaining"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 "Cipher Block Chaining for D40 Secure Messaging"
 *      - Below Cipher modes applicable only for CryptoSym mbedtls.
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CCM "Counter with Cipher Block Chaining-Message Authentication Code"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "Counter with Cipher Block Chaining-Message Authentication Code optional"
 *
 *  - To be ORed with Authentication Tag for CCM and CCM* operation modes
 *      - \ref PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available": \b pEncryptedBuffer will have Encrypted
 *        data only and not have Authentication tag data.
 *      - \ref PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available": \b pEncryptedBuffer will have Encrypted data
 *        followed by Authentication tag data.
 *
 *  - To be ORed with Buffering Flags
 *      - #PH_EXCHANGE_DEFAULT
 *      - The below ones are not supported by \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" and \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*"
 *        cipher modes. These are supported by other cipher modes.
 *          - #PH_EXCHANGE_BUFFER_FIRST
 *          - #PH_EXCHANGE_BUFFER_CONT
 *          - #PH_EXCHANGE_BUFFER_LAST
 *
 * \note
 *      - The input data length (\b pPlainBuffer and \b wBufferLength) needs to be a multiple of the current block size
 *      - The output buffer (\b pEncryptedBuffer) buffer allocation should be equal to input buffer (\b pPlainBuffer)
 *      - Cipher modes PH_CRYPTOSYM_CIPHER_MODE_CCM and PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR applicable only for CryptoSym mbedtls.
 *      - If \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" or \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*" cipher is used
 *          - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available"
 *              - Plain buffer can be any length but output buffer should be equal to Plain buffer length.
 *              - Tag information can be retrieved using \ref phCryptoSym_GetAuthenticationTag "Get Authentication Tag" interface.
 *          - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available"
 *              - Plain buffer can be any length but output buffer should be Plain Buffer Length + Tag Length.
 *              - Output Buffer will have Enciphered data followed by Tag data.
 *          - In both the case \b wOption = #PH_CRYPTOSYM_AUTH_TAG_OFF or #PH_CRYPTOSYM_AUTH_TAG_ON, Tag length should first be
 *            configured using \ref phCryptoSym_GetConfig "GetConfig" with \ref PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "Tag Length"
 *            as configuration identifier.
 *          - Only #PH_EXCHANGE_DEFAULT flag is supported.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        An unsupported key is loaded (or no key is loaded) or \b wBufferLength is not
 *                                          a multiple of the current block size.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    An unknown cipher option wOption is specified.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_Encrypt(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                       /**< [In] Option byte specifying the cipher mode and the update behavior of the IV */
        const uint8_t * pPlainBuffer,                                           /**< [In] Plain data buffer.
                                                                                 *          - Should always be in multiple of current block size.
                                                                                 *          - If not of current block size then \ref phCryptoSym_ApplyPadding
                                                                                 *            "Apply Padding" needs to be used to make it upto current block size.
                                                                                 *          - For CCM or CCM* cipher modes multiple of block size is not applicable.
                                                                                 */
        uint16_t  wBufferLength,                                                /**< [In] Length of plain and encrypted data buffer - needs to be a multiple of the
                                                                                 *        current block size
                                                                                 */
        uint8_t * pEncryptedBuffer                                              /**< [Out] Encrypted data buffer.
                                                                                 *          - Allocation should be Should be equal to \b pPlainBuffer.
                                                                                 *          - For CCM or CCM* cipher modes,
                                                                                 *              - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available":
                                                                                 *                Should be equal to \b pPlainBuffer.
                                                                                 *              - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available":
                                                                                 *                Should be equal to \b pPlainBuffer + Authentication Tag length to store
                                                                                 *                Encrypted data + Authentication Tag.
                                                                                 */
    );

/**
 * \brief Perform Decryption with one of the supported crypto modes
 *
 * The \b wOption word specifies the operation mode to use, Authentication Tag information for Encryption and the update behavior of the IV.
 * All modes of operation are coded in the LSB, the flags in the MSB.
 *  - The following Cipher modes are supported:
 *      - #PH_CRYPTOSYM_CIPHER_MODE_ECB "Electronic Code Book"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CBC "Cipher Block Chaining"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CBC_DF4 "Cipher Block Chaining for D40 Secure Messaging"
 *      - Below Cipher modes applicable only for CryptoSym mbedtls.
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CCM "Counter with Cipher Block Chaining-Message Authentication Code"
 *      - #PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "Counter with Cipher Block Chaining-Message Authentication Code optional"
 *
 * - To be ORed with Authentication Tag for CCM and CCM* operation modes
 *      - #PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available": \b pEncryptedBuffer will have Encrypted
 *        data only and not have Authentication tag data.
 *      - #PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available": \b pEncryptedBuffer will have Encrypted
 *        data followed by Authentication tag data.
 *  - To be ORed with Buffering Flags
 *      - #PH_EXCHANGE_DEFAULT
 *      - The below ones are not supported by \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" and \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*"
 *        cipher modes. These are supported by other cipher modes.
 *      - #PH_EXCHANGE_BUFFER_FIRST
 *      - #PH_EXCHANGE_BUFFER_CONT
 *      - #PH_EXCHANGE_BUFFER_LAST
 *
 * \note
 *      - The input data length (\b pPlainBuffer and \b wBufferLength) needs to be a multiple of the current block size
 *      - The output buffer (\b pEncryptedBuffer) buffer allocation should be equal to input buffer (\b pPlainBuffer)
 *      - Cipher modes PH_CRYPTOSYM_CIPHER_MODE_CCM and PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR applicable only for CryptoSym mbedtls.
 *      - If \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" or \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*" cipher is used,
 *          - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available"
 *              - Tag information should be configured using \ref phCryptoSym_SetAuthenticationTag "Set Authentication Tag" interface.
 *              - Plain buffer should have the Encrypted information only. Authentication Tag information should not be available.
 *          - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available"
 *              - Input buffer should be Input Length + Tag Length and Output buffer should be equal to Input buffer length.
 *              - Output Buffer will have Plain data followed by Tag data. User should discard the last bytes based on Tag Length and
 *                capture only the deciphered data.
 *              - Tag length should first be configured using \ref phCryptoSym_GetConfig "GetConfig" with
 *                \ref PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "Tag Length" as configuration identifier.
 *          - Only #PH_EXCHANGE_DEFAULT flag is supported.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        An unsupported key is loaded (or no key is loaded) or \b wBufferLength is not
 *                                          a multiple of the current block size.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    An unknown cipher option wOption is specified.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_Decrypt(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                       /**< [In] Option byte specifying the cipher mode and the update behavior of the IV */
        uint8_t * pEncryptedBuffer,                                             /**< [In] Encrypted data buffer.
                                                                                 *          - Should always be in multiple of current block size.
                                                                                 *          - If not of current block size then \ref phCryptoSym_ApplyPadding
                                                                                 *            "Apply Padding" needs to be used to make it upto current block size.
                                                                                 *          - For CCM or CCM* cipher modes multiple of block size is not applicable.
                                                                                 */
        uint16_t  wBufferLength,                                                /**< [In] Length of plain and encrypted data buffer - needs to be a multiple of the
                                                                                 *        current block size.
                                                                                 */
        uint8_t * pPlainBuffer                                                  /**< [Out] Plain data buffer.
                                                                                 *          - Shall be in multiple of current block size. Plain data may be padded
                                                                                 *            with zeros if not current block size and needs to be removed using
                                                                                 *            \ref phCryptoSym_RemovePadding "Remove Padding" interface.
                                                                                 *          - For CCM or CCM* cipher modes,
                                                                                 *              - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_OFF "Authentication Tag not available":
                                                                                 *                Should be equal to \b pPlainBuffer.
                                                                                 *              - \b wOption = \ref PH_CRYPTOSYM_AUTH_TAG_ON "Authentication Tag Available":
                                                                                 *                Will contain the decrypted data. User has to remove Tag Length from the input
                                                                                 *                length specified
                                                                                 */
    );

/**
 * \brief Calculate MAC with one of the supported MAC modes
 *
 * The option word specifies the MAC mode to use and the update behavior of the IV as well as the completion behavior.
 * All modes of operation are coded in the LSB, the flags in the MSB.
 * The following Cipher modes are supported:
 * - #PH_CRYPTOSYM_MAC_MODE_CMAC "Cipher-Based Message Authentication Code"
 * - #PH_CRYPTOSYM_MAC_MODE_CBCMAC "Cipher Block Chaining Message Authentication Code"
 *
 * The following Flags are supported:
 * - #PH_EXCHANGE_DEFAULT
 * - #PH_EXCHANGE_BUFFER_FIRST
 * - #PH_EXCHANGE_BUFFER_CONT
 * - #PH_EXCHANGE_BUFFER_LAST
 *
 * Note: If #PH_EXCHANGE_BUFFERED_BIT is set, the input length needs to be a multiple of the block length!
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        An unsupported key is loaded (or no key is loaded) or wDataLength is not
 *                                          a multiple of the current block size and the option #PH_EXCHANGE_BUFFERED_BIT is set.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    An unknown mac option wOption is specified.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_CalculateMac(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                       /**< [In] Option byte specifying the MAC mode and the update behavior of
                                                                                 *        the IV and the completion flag.
                                                                                 */
        const uint8_t * pData,                                                  /**< [In] Input data on which the MAC needs to be computed.
                                                                                 *        Input will be always be in multiple of current block size if wOption is
                                                                                 *          - #PH_EXCHANGE_BUFFER_FIRST
                                                                                 *          - #PH_EXCHANGE_BUFFER_CONT
                                                                                 */
        uint16_t  wDataLength,                                                  /**< [In] number of input data bytes */
        uint8_t * pMac,                                                         /**< [Out] Output MAC block; uint8_t[16] */
        uint8_t * pMacLength                                                    /**< [Out] Length of MAC */
    );

/**
 * \brief Load Initialization vector
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        \b bIVLength does not match the current block size.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_LoadIv(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        const uint8_t * pIV,                                                    /**< [In] Initialization vector to use. Should of current block size. */
        uint8_t bIVLength                                                       /**< [In] Length of bytes available in \b pIV buffer. */
    );

/**
 * \brief Load Initialization vector (Nonce).
 * Can be used for below cipher modes
 *  - #PH_CRYPTOSYM_CIPHER_MODE_CCM "Counter with Cipher Block Chaining-Message Authentication Code"
 *  - #PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "Counter with Cipher Block Chaining-Message Authentication Code optional"
 *
 *  \note
 *        - Support is available for mBedTLS component only or based on DUT feature support.
 *        - <b>This API is not applicable for PN7642.</b>
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        - \b bNonceLen does not match with  7, 8, 9, 10, 11, 12, or 13 in case of
 *                                            \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "Counter with Cipher Block Chaining-Message Authentication Code" or
 *                                            \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "Counter with Cipher Block Chaining-Message Authentication Code optional"
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_LoadNonce(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bCipher,                                                        /**< [In] One of the cipher modes mentioned in the description. */
        const uint8_t * pNonce,                                                 /**< [In] Initialization vector to use. Should based on cipher mode. */
        uint8_t bNonceLen                                                       /**< [In] Length of bytes available in \b pNonce buffer. */
    );

/**
 * \brief Load Additional Data Field.
 * This will be used by \ref phCryptoSym_Encrypt "Encrypt" and \ref phCryptoSym_Decrypt "Decrypt"
 * when Cipher Mode is \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM" and \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*".
 *
 *  \note <b>This API is not applicable for PN7642.</b>
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        \b pAddData is Null
 * \retval #PH_ERR_PARAMETER_SIZE           \b wAddData_Len is higher than the maximum allowed one.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_LoadAdditionalData(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        const uint8_t * pAddData,                                               /**< [In] Additional Data to use for CCM cipher mode. */
        uint16_t wAddData_Len                                                   /**< [In] Length of bytes available in \b pAddData buffer.
                                                                                 *        Maximum size should be less than 2^16 - 2^8 = 65280.
                                                                                 */
    );

/**
 * \brief Load Key
 *
 * This function uses the key storage provided at component initialization to retrieve the key identified by wKeyNo and wKeyVersion.
 * After retrieving the key is loaded into the internal key storage array to be prepared for subsequent cipher operations.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 *                                          - No KeyStore specified at initialization.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    Key Type not supported.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_LoadKey(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] Key number in KeyStore to be loaded. */
        uint16_t wKeyVersion,                                                   /**< [In] Key Version in KeyStore to be loaded. */
        uint16_t wKeyType                                                       /**< [In] Type of Key to be loaded. Supported ones are
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES128 "AES 128Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES192 "AES 192Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES256 "AES 256Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_DES "DES Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_2K3DES "TripleDES - 2Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_3K3DES "TripleDES - 3Key"
                                                                                 */
    );

/**
 * \brief Direct Load Key
 *
 * The key provided in the pKey parameter is loaded into the internal key storage array to be prepared for subsequent cipher operations.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    Key Type not supported.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_LoadKeyDirect(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        const uint8_t* pKey,                                                    /**< [In] Key to be loaded. Number of bytes should be based on the key
                                                                                 *        type mentioned in \b wKeyType parameter.
                                                                                 */
        uint16_t wKeyType                                                       /**< [In] Type of Key to be loaded. Supported ones are
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES128 "AES 128Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES192 "AES 192Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES256 "AES 256Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_DES "DES Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_2K3DES "TripleDES - 2Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_3K3DES "TripleDES - 3Key"
                                                                                 */
    );

/**
 * \brief Diversify Key - Note: This function invalidates the currently loaded key.
 *
 * Using the key stored in the KeyStore passed at initialization of the component and identified by wKeyNo and wKeyVersion
 * this function calculates a diversified key according to the wOption specified that can be used in different applications.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 *                                          - No KeyStore specified at Initialization.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    Key Type not supported (for key diversification).
 * \retval #PH_ERR_LENGTH_ERROR             Length of diversification input is wrong.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_DiversifyKey(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                       /**< [In] Option to specify the diversification method.
                                                                                 *        One of the below mentioned information.
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_DESFIRE
                                                                                 *            "DESFire Key Diversification Mode". To be used along with
                                                                                 *              - #PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL "Full Key"
                                                                                 *              - #PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF "Half Key"
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS
                                                                                 *            "PLUS Key Diversification Mode".
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_MIFARE_ULTRALIGHT
                                                                                 *            "Ultralight Key Diversification Mode".
                                                                                 */
        uint16_t wKeyNo,                                                        /**< [In] Key number in KeyStore to be loaded */
        uint16_t wKeyVersion,                                                   /**< [In] Key Version in KeyStore to be loaded */
        uint8_t * pDivInput,                                                    /**< [In] Diversification Input used to diversify the key. */
        uint8_t  bLenDivInput,                                                  /**< [In] Length of diversification input used to diversify the key.
                                                                                 *        If 0, no diversification is performed.
                                                                                 */
        uint8_t * pDiversifiedKey                                               /**< [Out] Diversified key. Will be of current block size. */
    );

/**
 * \brief Diversify Direct Key - Note: This function invalidates the currently loaded key.
 *
 * Using the key passed in the pKey parameter this function calculates a diversified key according to the wOption
 * specified that can be used in different applications.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER    Key Type not supported (for key diversification).
 * \retval #PH_ERR_LENGTH_ERROR             Length of diversification input is wrong.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_DiversifyDirectKey(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                       /**< [In] Option to specify the diversification method.
                                                                                 *        One of the below mentioned information.
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_DESFIRE
                                                                                 *            "DESFire Key Diversification Mode". To be used along with
                                                                                 *              - #PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL "Full Key"
                                                                                 *              - #PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF "Half Key"
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS
                                                                                 *            "PLUS Key Diversification Mode".
                                                                                 *          - #PH_CRYPTOSYM_DIV_MODE_MIFARE_ULTRALIGHT
                                                                                 *            "Ultralight Key Diversification Mode".
                                                                                 */
        uint8_t * pKey,                                                         /**< [In] Key to be loaded. Number of bytes should be based on the key
                                                                                 *        type mentioned in \b wKeyType parameter.
                                                                                 */
        uint16_t wKeyType,                                                      /**< [In] Type of Key to be loaded. Supported ones are
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES128 "AES 128Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES192 "AES 192Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_AES256 "AES 256Bit Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_DES "DES Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_2K3DES "TripleDES - 2Key"
                                                                                 *      - #PH_CRYPTOSYM_KEY_TYPE_3K3DES "TripleDES - 3Key"
                                                                                 */
        uint8_t * pDivInput,                                                    /**< [In] Diversification Input used to diversify the key. */
        uint8_t bLenDivInput,                                                   /**< [In] Length of diversification input used to diversify the key.
                                                                                 *        If 0, no diversification is performed.
                                                                                 */
        uint8_t * pDiversifiedKey                                               /**< [Out] Diversified key. Will be of current block size. */
    );

/**
 * \brief Apply Padding to a given data buffer.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_BUFFER_OVERFLOW          \b wDataOutBufSize is too small.
 * \retval #PH_ERR_INVALID_PARAMETER        Unsupported bOption.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_ApplyPadding(
        uint8_t bOption,                                                        /**< [In] Specifies padding mode
                                                                                 *          - #PH_CRYPTOSYM_PADDING_MODE_1 "Zero Padding"
                                                                                 *          - #PH_CRYPTOSYM_PADDING_MODE_2 "Zero Padding with MSB Bit Set"
                                                                                 */
        const uint8_t *  pDataIn,                                               /**< [In] Input data for which padding is required. */
        uint16_t wDataInLength,                                                 /**< [In] Length of bytes available in \b pDataIn buffer. */
        uint8_t bBlockSize,                                                     /**< [In] Block size to be used for padding. */
        uint16_t wDataOutBufSize,                                               /**< [In] Size of output data buffer. */
        uint8_t * pDataOut,                                                     /**< [Out] Output data containing the information with padded bytes added. */
        uint16_t * pDataOutLength                                               /**< [Out] Length of bytes available in \b pDataOut buffer. */
    );

/**
 * \brief Remove Padding to a given data buffer.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_PARAMETER        Unsupported \b bOption or \b wDataInLength is not a multiple of the bBlockSize parameter.
 * \retval #PH_ERR_FRAMING_ERROR            Padding byte wrong. Expected 80h as the first padding byte if \b bOption = #PH_CRYPTOSYM_PADDING_MODE_2.
 *                                          "Zero Padding with MSB Bit Set".
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_RemovePadding(
        uint8_t bOption,                                                        /**< [In] Specifies padding mode
                                                                                 *          - #PH_CRYPTOSYM_PADDING_MODE_1 "Zero Padding"
                                                                                 *          - #PH_CRYPTOSYM_PADDING_MODE_2 "Zero Padding with MSB Bit Set"
                                                                                 */
        const uint8_t * pDataIn,                                                /**< [In] Input data from which padding should be removed. */
        uint16_t wDataInLength,                                                 /**< [In] Length of bytes available in \b pDataIn buffer */
        uint8_t bBlockSize,                                                     /**< [In] Block size to be used for padding */
        uint16_t wDataOutBufSize,                                               /**< [In] Size of output data buffer */
        uint8_t * pDataOut,                                                     /**< [Out] Output data containing the information with padded bytes removed. */
        uint16_t * pDataOutLength                                               /**< [Out] Length of bytes available in \b pDataOut buffer */
    );

/**
 * \brief Set configuration parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER         Valid wConfig but invalid wValue for that config.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER     Invalid (Unsupported) wConfig.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_SetConfig(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier. One of the below mentioned ones,
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_KEEP_IV "Save Initialization Vector"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "CCM or CCM* Tag Length"
                                                                                 *          \cond NXPBUILD__PH_CRYPTOSYM_LRP
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_LRP "Configure LRP"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_LRP_NUMKEYS_UPDATE "Update LRP Keys"
                                                                                 *          \endcond
                                                                                 */
        uint16_t wValue                                                         /**< [In] Configuration Value for the provided configuration identifier.
                                                                                 *          - Refer \ref phCryptoSym_Defines_KeepIV "KeepIV Options" for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_KEEP_IV "Keep IV" configuration identifier.
                                                                                 *          \cond NXPBUILD__PH_CRYPTOSYM_LRP
                                                                                 *          - #PH_ON to enable LRP and #PH_OFF to disable LRP are the valid values for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_LRP configuration identifier.
                                                                                 *          \endcond
                                                                                 */
    );

/**
 * \brief Get configuration parameter.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not
 *                                            supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER         Value behind wConfig not valid at the moment.
 * \retval #PH_ERR_UNSUPPORTED_PARAMETER     Invalid (Unsupported) wConfig.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_GetConfig(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier. One of the below mentioned ones,
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_KEY_TYPE "Key Type"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_KEY_SIZE "Key Size"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_BLOCK_SIZE "Block Size"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_KEEP_IV "Save Initialization Vector"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_ADDITIONAL_INFO "Additional Information"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_CCM_TAG_LENGTH "CCM or CCM* Tag Length"
                                                                                 *          \cond NXPBUILD__PH_CRYPTOSYM_LRP
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_LRP "Configure LRP"
                                                                                 *          - #PH_CRYPTOSYM_CONFIG_LRP_NUMKEYS_UPDATE "Update LRP Keys"
                                                                                 *          \endcond
                                                                                 */
        uint16_t * pValue                                                       /**< [Out] Configuration Value for the provided configuration identifier.
                                                                                 *          - Refer \ref phCryptoSym_Defines_KeyTypes "Supported Key Types" for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_KEY_TYPE "Key Type" configuration identifier.
                                                                                 *          - Refer \ref phCryptoSym_Defines_KeySize_DES "DES Key / Block Sizes" or
                                                                                 *            \ref phCryptoSym_Defines_KeySize_AES "AES Key / Block Sizes" for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_KEY_SIZE "Key Size" or
                                                                                 *            #PH_CRYPTOSYM_CONFIG_BLOCK_SIZE "Block Size" configuration identifier.
                                                                                 *          - Refer \ref phCryptoSym_Defines_KeepIV "KeepIV Options" for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_KEEP_IV "Keep IV" configuration identifier.
                                                                                 *          \cond NXPBUILD__PH_CRYPTOSYM_LRP
                                                                                 *          - #PH_ON to enable LRP and #PH_OFF to disable LRP are the valid values for
                                                                                 *            #PH_CRYPTOSYM_CONFIG_LRP configuration identifier.
                                                                                 *          \endcond
                                                                                 */
    );

/**
 * \brief Load Authentication Tag information.
 * This will be used by \ref phCryptoSym_Decrypt "Decrypt" when Cipher Mode is \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM"
 * and \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*". Refer \ref phCryptoSym_Decrypt "Decrypt" for more information.
 *
 * \note <b>This API is not applicable for PN7642.</b>
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS
 *                                          - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        - \b pTag is Null
 *                                          - \b bTag_Len is higher than the maximum allowed one which is 16 bytes.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_SetAuthenticationTag(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        const uint8_t * pTag,                                                   /**< [In] Authentication tag to use for CCM or CCM* decryption. */
        uint8_t bTag_Len                                                        /**< [In] Length of bytes available in \b pTag buffer. */
    );

/**
 * \brief Get Authentication Tag information.
 * This will be used by \ref phCryptoSym_Encrypt "Encrypt" when Cipher Mode is \ref PH_CRYPTOSYM_CIPHER_MODE_CCM "CCM"
 * and \ref PH_CRYPTOSYM_CIPHER_MODE_CCM_STAR "CCM*". Refer \ref phCryptoSym_Encrypt "Encrypt" for more information.
 *
 * \note <b>This API is not applicable for PN7642.</b>
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS      - If the interface context (\b pDataparams) is not holding this layer ID.
 *                                          - If the component context holds a different sub-component ID that is not supported by this layer.
 * \retval #PH_ERR_INVALID_PARAMETER        \b pTag and \b pTag_Len is Null
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_GetAuthenticationTag(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint8_t * pTag,                                                         /**< [In] Authentication tag generated for CCM or CCM* encryption. */
        uint8_t * pTag_Len                                                      /**< [In] Length of bytes available in \b pTag buffer. */
    );

/**
 * \brief Returns the status code and respective message. This interfaces is supported only if CryptoSym component is
 *  initialized with \ref phCryptoSym_mBedTLS_Init "mBedTLS Initialization".
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoSym_GetLastStatus(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wStatusMsgLen,                                                     /**< [In] Size of bytes allocated for \b pStatusMsg parameter. */
        int8_t * pStatusMsg,                                                        /**< [Out] The equivalent status message for the information available in \b pStatusCode. */
        int32_t * pStatusCode                                                       /**< [Out] The status code returned by the underlying Crypto library. */
    );

/**
 * \brief Gets the size of the key.
 *
 * \return Status code
 * \retval 0        : If the \b wKeyType is not supported.
 * \retval Any Value: Size for the mentioned \b wKeyType information.
 */
uint16_t phCryptoSym_GetKeySize(uint16_t wKeyType);

/**
 * end of group phCryptoSym
 * @}
 */
#endif /* NXPBUILD__PH_CRYPTOSYM */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* PHCRYPTOSYM_H */
