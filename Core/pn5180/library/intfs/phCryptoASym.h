/*----------------------------------------------------------------------------*/
/* Copyright 2021 - 2022, 2024 - 2025 NXP                                     */
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
* Generic ASymmetric Cryptography Component of the Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOASYM_H
#define PHCRYPTOASYM_H

#include <ph_Status.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS

#define PH_CRYPTOASYM_MBEDTLS_ID                                            0x01U   /**< ID for mBedTLS Software crypto component. */
#include <mbedtls/ecp.h>

/** \addtogroup phCryptoASym_mBedTLS Component : mbedTLS
 * \brief mBedTLS Sub-Component ASymmetric Cryptography library.
 * @{
 */
#ifndef PH_CRYPTOASYM_SHA256
#if defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA256_ALT)
/** \brief Enables MD5 Hashing support. */
#define PH_CRYPTOASYM_SHA256
#endif /* MBEDTLS_SHA256_C */
#endif /* PH_CRYPTOASYM_SHA256 */

#ifndef PH_CRYPTOASYM_SHA512
#if defined(MBEDTLS_SHA512_C) || defined(MBEDTLS_SHA512_ALT)
/** \brief Enables MD5 Hashing support. */
#define PH_CRYPTOASYM_SHA512
#endif /* MBEDTLS_SHA512_C */
#endif /* PH_CRYPTOASYM_SHA512 */

/** \brief Data Structure to save details of ECC KeyPai information. */
typedef struct
{
    mbedtls_ecp_group stGroup;                                                      /**< Member to save the Group information of the ECC KeyPair.
                                                                                     *   Details will be like the Curve info, its parameters etc.
                                                                                     */
    mbedtls_ecp_point stPoint;                                                      /**< Member to save the point information of the ECC KeyPair.
                                                                                     *   Details will basically be the Public Key.
                                                                                     */
    mbedtls_mpi stMpi;                                                              /**< Member to save the MPI information of the ECC KeyPair.
                                                                                     *   Details will basically be the Private / Secret Key.
                                                                                     */
}phCryptoASym_mBedTLS_ECC_KeyPair;

/** \brief Data structure for ASymmetric Crypto mBedTLS layer implementation. */
typedef struct
{
    uint16_t wId;                                                                   /**< Layer ID for this component, NEVER MODIFY! */
    void * pKeyStoreDataParams;                                                     /**< Pointer to Key Store object. */
    void * pCtx;                                                                    /**< Pointer to underlying ASymmetric Crypto context for storing KeyPair information.
                                                                                     *      - Will be utilized internally by the implementation.
                                                                                     *      - Will store \ref phCryptoASym_mBedTLS_ECC_KeyPair "ECC Key-Pair" context.
                                                                                     */
    uint16_t wKeyType;                                                              /**< Key Type. */
    uint8_t bCurveID;                                                               /**< ECC Curve Id. */
    uint8_t bHashAlgo;                                                              /**< Hash Algorithm ID. */
    int32_t dwErrorCode;                                                            /**< Error code returned by mbedTLS layer. */
    uint8_t * pBuffer;                                                              /**< Internal Buffer for processing. */
    uint16_t wBufferSize;                                                           /**< Size of bytes allocated for \b pBuffer member. */
} phCryptoASym_mBedTLS_DataParams_t;

/**
 * \brief Initialize the CryptoASym with mBedTLS as sub-component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_mBedTLS_Init(
        phCryptoASym_mBedTLS_DataParams_t * pDataParams,                            /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                                 /**< [In] Specifies the size of the data parameter structure. */
        void * pKeyStoreDataParams,                                                 /**< [In] Pointer to a key store structure (can be null).*/
        uint8_t * pBuffer,                                                          /**< [In] Size of global buffer. This buffer is for processing information internally.
                                                                                     *        Should not be less than the default specified one (which is 256 bytes).
                                                                                     */
        uint16_t wBufferSize                                                        /**< [In] Size of bytes allocated for \b pBuffer parameter.*/
    );

/**
 * \brief De-Initialize the CryptoASym with mBedTLS as sub-component.
 * \note Its must to call this interface to De-Initialize any used global context from other libraries.
 * If not called, there might be unusual behavior for the next executions.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_mBedTLS_DeInit(
        phCryptoASym_mBedTLS_DataParams_t * pDataParams                             /**< [In] Pointer to this layer's parameter structure. */
    );

/**
 * end of group phCryptoASym_mBedTLS
 * @}
 */
#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */

#ifdef NXPBUILD__PH_CRYPTOASYM

/** \addtogroup phCryptoASym CryptoASym
 *
 * \brief This is only a wrapper layer to abstract the different Crypto ASymmetric implementations.
 * With this wrapper it is possible to support more than one ASymmetric implementation
 * in parallel, by adapting this wrapper.
 *
 * Important hints for users of this component:
 * - Before use of any function, the dedicated crypto implementation has to be initialized using interface mentioned below.
 *      - \ref phCryptoASym_mBedTLS_Init "mBedTLS Initialization"
 * - Functions using a KeyStore (\ref phCryptoASym_ECC_LoadKey "Load ECC Key") are only available if KeyStore component has been passed during
 *   component initialization.
 * - If return value is \ref PH_ERR_INTERNAL_ERROR "Internal Error", means error has occurred in the dependent ASymmetric crypto library.
 *   Call \ref phCryptoASym_GetLastStatus "GetLastStatus" to know about the error details.
 * - Public Key can alone be loaded separately. But if Private Key is loaded, then its must to load PublicKey.
 *   If public key is not loaded after PrivateKey, then while Exporting Private key, error will be observed.
 * - While computing SharedSecret, its must to have a key-pair available using one of the below mentioned interfaces,
 *      - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
 *      - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
 *      - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
 * @{
 */

 /** \defgroup phCryptoASym_Errors ErrorCodes
 * \brief These component implement the Crypto ASymmetric custom Error codes.
 * @{
 */
#define PH_ERR_UNSUPPORTED_CURVE_ID                     (PH_ERR_CUSTOM_BEGIN + 0U)  /**< Curve by group ID not supported. */
#define PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE                (PH_ERR_CUSTOM_BEGIN + 1U)  /**< Type of Key Pair to be loaded /exported is not supported. */
#define PH_ERR_UNSUPPORTED_HASH_ALGO                    (PH_ERR_CUSTOM_BEGIN + 2U)  /**< Hashing Algorithm not supported. */
#define PH_ERR_VERIFICATION_FAILED                      (PH_ERR_CUSTOM_BEGIN + 3U)  /**< Verification of Message / Signature combination failed. */
/**
 * end of group phCryptoASym_Errors
 * @}
 */

/** \defgroup phCryptoASym_CommonDefs Common Definitions
 * \brief These are common definitions for most of the Crypto commands.
 * @{
 */

/** \defgroup phCryptoASym_CommonDefs_KeyTypes Defines_KeyType
 * \brief Options describing about the supported keytypes.
 * @{
 */
#define PH_CRYPTOASYM_KEY_TYPE_INVALID                                      0xFFFFU /**< Invalid Key Type. */
#define PH_CRYPTOASYM_KEY_TYPE_ECC                                          0x0200U /**< ASymmetric ECC (Elliptical Curve Cryptography) key type. */
/**
 * end of group phCryptoASym_CommonDefs_KeyTypes
 * @}
 */

/** \defgroup phCryptoASym_CommonDefs_KeyPair Defines_KeyPair
 * \brief Type of ASymmetric Key to be exported or loaded.
 * @{
 */
#define PH_CRYPTOASYM_KEYPAIR_MASK                                          0xF000U /**< Masking the Key-Pair information. */
#define PH_CRYPTOASYM_KEY_PAIR_INVALID                                      0xC000U /**< ASymmetric key pair as Invalid. */
#define PH_CRYPTOASYM_PRIVATE_KEY                                           0x1000U /**< Load / Export Private Key. */
#define PH_CRYPTOASYM_PUBLIC_KEY                                            0x2000U /**< Load / Export Public Key. */
/**
 * end of group phCryptoASym_CommonDefs_KeyPair
 * @}
 */

/** \defgroup phCryptoASym_CommonDefs_HashAlgos Defines_HashAlgorithms
 * \brief Supported Hashing algorithms. Also known as Message Digest (MD).
 * @{
 */
#define PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE                                  0U  /**< None. Hashing will not be performed for the message. */

#ifdef PH_CRYPTOASYM_SHA256
#define PH_CRYPTOASYM_HASH_ALGO_SHA224                                          3U  /**< The SHA-224 hashing algorithm. */
#define PH_CRYPTOASYM_HASH_ALGO_SHA256                                          4U  /**< The SHA-256 hashing algorithm. */
#endif /* PH_CRYPTOASYM_SHA256 */

#ifdef PH_CRYPTOASYM_SHA512
#define PH_CRYPTOASYM_HASH_ALGO_SHA384                                          5U  /**< The SHA-384 hashing algorithm. */
#define PH_CRYPTOASYM_HASH_ALGO_SHA512                                          6U  /**< The SHA-512 hashing algorithm. */
#endif /* PH_CRYPTOASYM_SHA512 */
/**
 * end of group phCryptoASym_CommonDefs_HashAlgos
 * @}
 */

/**
 * end of group phCryptoASym_CommonDefs
 * @}
 */

/* CryptoASym Hash related commands ---------------------------------------------------------------------------------------------------- */
/** \defgroup phCryptoASym_Hash Commands_Hash
 * \brief Describes about the ASymmetric Crypto's Hash related commands.
 * @{
 */

/**
 * \brief Computes Hash for the given message.
 * \note Start, Update and Finish operation are supported and can be exercised by using \b wOption parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_UNSUPPORTED_HASH_ALGO    Hash Algorithm not supported. Refer \b bHashAlgo parameter description.
 * \retval #PH_ERR_INVALID_PARAMETER        - If Hashing algorithm is \ref PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE "No-Hashing"
 *                                            and buffering options is not #PH_EXCHANGE_DEFAULT.
 *                                          - If the buffers are null.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ComputeHash(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure */
        uint16_t wOption,                                                           /**< [In] Buffering options for Hashing the message. These flags can be used
                                                                                     *        for intermediate Hash operation
                                                                                     *          - #PH_EXCHANGE_DEFAULT     : Computes the Hash for the Message and returns the Hash.
                                                                                     *                                       This performs Start, Update and Finish in one operation.
                                                                                     *          - #PH_EXCHANGE_BUFFER_FIRST: Computes the Hash and saves for completion. This is
                                                                                     *                                       equivalent to Start and here the Hash is not provided.
                                                                                     *          - #PH_EXCHANGE_BUFFER_CONT : Computes the Hash along with the previous hash data
                                                                                     *                                       and saves for completion. This is equivalent to Update
                                                                                     *                                       and here the Hash is not provided.
                                                                                     *          - #PH_EXCHANGE_BUFFER_LAST : Computes the Hash along with the previous hash data.
                                                                                     *                                       This is equivalent to Finish and here the Hash is provided.
                                                                                     */
        uint8_t bHashAlgo,                                                          /**< [In] Hashing Algorithm to use. Refer \ref phCryptoASym_CommonDefs_HashAlgos
                                                                                     *        "Hash Algorithm".
                                                                                     */
        uint8_t * pMessage,                                                         /**< [In] Input message to be Hashed. */
        uint16_t wMsgLen,                                                           /**< [In] Length of bytes available in \b pMessage buffer. */
        uint8_t * pHash,                                                            /**< [Out] The Hashed information for the message based on hashing algorithm. */
        uint16_t * pHashLen                                                         /**< [Out] Length of bytes available in \b pHash buffer. */
    );
/**
 * end of group phCryptoASym_Hash
 * @}
 */

/* CryptoASym ECC related commands ----------------------------------------------------------------------------------------------------- */
/** \defgroup phCryptoASym_ECC Commands_ECC
 * \brief Describes about the ASymmetric Crypto's ECC related commands.
 * @{
 */

/**
 * \defgroup phCryptoASym_ECC_Defines Defines
 * \brief Macro Definitions for ASymmetric Crypto's ECC interface support.
 * @{
 */

/** \defgroup phCryptoASym_ECC_Defines_CurveID CurveID
 * \brief Options describing supported ECC Curve ID's.
 * @{
 */
#define PH_CRYPTOASYM_CURVE_ID_MASK                                     0x000FU     /**< Masking of CurveID's. */
#define PH_CRYPTOASYM_CURVE_ID_NONE                                     0x0000U     /**< ECC Curve ID as none. */

#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_SECP192R1                                0x0001U     /**< Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1. */
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_SECP224R1                                0x0002U     /**< Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1. */
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_SECP256R1                                0x0003U     /**< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_SECP384R1                                0x0004U     /**< Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1. */
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1                           0x0006U     /**< Domain parameters for 256-bit BrainPool curve. */
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
#define PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1                           0x0007U     /**< Domain parameters for 384-bit BrainPool curve. */
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */
/**
 * end of group phCryptoASym_ECC_Defines_CurveID
 * @}
 */

/**
 * end of group phCryptoASym_ECC_Defines
 * @}
 */

/**
 * \brief Generates a ECC Private and Public Key pair based on the ECC Curve name specified.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                  Operation successful.
 * \retval #PH_ERR_UNSUPPORTED_CURVE_ID     CurveID not supported. Refer \b bCurveID parameter description.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_GenerateKeyPair(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure */
        uint8_t bCurveID                                                            /**< [In] The \ref phCryptoASym_ECC_Defines_CurveID "Curve ID's" to be used
                                                                                     *        for key generation.
                                                                                     */
    );

/**
 * \brief Exports the ECC Private or Public key based on the option provided.
 *
 * \note
 *       This interface needs to be called post using one of the below mentioned interfaces,
 *          - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
 *          - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
 *          - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS                      Operation successful.
 * \retval #PH_ERR_KEY                          KeyPair not loaded or generated. Refer description notes for more information.
 * \retval #PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE    Export Key pair type is not supported. Refer \b wOption parameter description.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_ExportKey(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure */
        uint16_t wOption,                                                           /**< [In] Combined values for Key to export, the format to be used and
                                                                                     *        internal key context to be used while exporting the keys.
                                                                                     *          - Supported Keys to export are
                                                                                     *              - \ref PH_CRYPTOASYM_PRIVATE_KEY "Private Key"
                                                                                     *              - \ref PH_CRYPTOASYM_PUBLIC_KEY "Public Key"
                                                                                     */
        uint16_t wKeyBuffSize,                                                      /**< [In] Size of bytes allocated for \b pKey parameter description. */
        uint8_t * pCurveID,                                                         /**< [Out] \ref phCryptoASym_ECC_Defines_CurveID "Curve ID" of the key being exported. */
        uint8_t * pKey,                                                             /**< [Out] The generated key based on the option provided.
                                                                                     *         The keys will be exported from either of the below interfaces,
                                                                                     *         - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
                                                                                     *         - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
                                                                                     *         - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
                                                                                     */
        uint16_t * pKeyLen                                                          /**< [Out] Length of bytes in \b pKey buffer. */
    );

/**
 * \brief Perform ECC Key Loading from KeyStore.
 * This function uses the key storage provided at component initialization to retrieve the key identified by wKeyNo.
 * After retrieving the key is loaded into the internal key storage array to be prepared for subsequent crypto operations.
 *
 * \note
 *      - Before calling this interface make sure the Private, Public Keys are loaded to KeyStore.
 *
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_KEY                          The KeyType available in \b wKeyNo is not of ECC Key Type.
 * \retval #PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE    Load Key type is not supported. Refer \b wOption parameter description.
 * \retval #PH_ERR_UNSUPPORTED_CURVE_ID         Curve ID not supported. Refer \b wOption parameter description.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_LoadKey(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                           /**< [In] Internal key context and Key-Pair to be used while loading the keys.
                                                                                     *          - Refer \ref phCryptoASym_CommonDefs_KeyPair "Key Pair" to load.
                                                                                     */
        uint16_t wKeyNo,                                                            /**< [In] Key number in KeyStore to be loaded. */
        uint16_t wPos                                                               /**< [In] Key Position in KeyStore to be loaded. */
    );

/**
 * \brief Direct Loads a ECC private and Public Key.
 * The key provided in the \b pKey parameter is loaded directly into the internal key context and will
 * be utilized for subsequent crypto operations.
 *
 * \note
 *      - This interface should be called more than ones to load Private or Public Key.
 *      - This interface supports loading of Private or Public Key separately.
 *      - This interface supports loading of Private or Public Key alone.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE    Load Key type is not supported. Refer \b wOption parameter description.
 * \retval #PH_ERR_UNSUPPORTED_CURVE_ID         Curve ID not supported. Refer \b wOption parameter description.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_LoadKeyDirect(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                           /**< [In] Combined values for Key to load, the format to be used and
                                                                                     *         internal context to be used while importing the keys.
                                                                                     *           - Refer \ref phCryptoASym_CommonDefs_KeyPair "Key Pair" to load.
                                                                                     *           - Refer \ref phCryptoASym_ECC_Defines_CurveID "Curve ID" of the Key to be loaded.
                                                                                     */
        uint8_t * pKey,                                                             /**< [In] The Private or Public key to be loaded. */
        uint16_t wKeyLen                                                            /**< [In] Length of bytes in \b pKey buffer. */
    );

/**
 * \brief Signs the message.
 *
 * \note
 *      - This interface needs to be called post using one of the below mentioned interfaces,
 *          - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
 *          - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
 *          - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
 *      - The \b pSign buffer allocation should be more than size of curve length to avoid memory corruption.
 *      - If the Message is small or needs to be computed in one call, then #PH_EXCHANGE_DEFAULT should be used for
 *        \b wOption parameter.
 *      - If the message is long enough and requires to be buffered, use #PH_EXCHANGE_BUFFER_FIRST,
 *        #PH_EXCHANGE_BUFFER_CONT and #PH_EXCHANGE_BUFFER_LAST options. The Signature will be provided when
 *        #PH_EXCHANGE_BUFFER_LAST is passed in \b wOption parameter.
 *      - If Hashing algorithm is \ref PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE "No-Hashing", then buffering options needs to be
 *        #PH_EXCHANGE_DEFAULT only. Other buffering options are not supported.
 *
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_KEY                      KeyPair not loaded or generated. Refer description notes for more information.
 * \retval #PH_ERR_UNSUPPORTED_HASH_ALGO    Hashing algorithm not supported. Refer \b bHashAlgo parameter description.
 * \retval #PH_ERR_INVALID_PARAMETER        If Hashing algorithm is \ref PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE "No-Hashing"
 *                                          and buffering options is not #PH_EXCHANGE_DEFAULT.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_Sign(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                           /**< [In] Buffering options combined with internal key context to use for signing.
                                                                                     *          - #PH_EXCHANGE_DEFAULT: Computes the Hash for the Message and
                                                                                     *                                  provides the Signature.
                                                                                     *          - #PH_EXCHANGE_BUFFER_FIRST: Computes the Hash and saves for completion.
                                                                                     *                                       Here the Signature is not provided.
                                                                                     *          - #PH_EXCHANGE_BUFFER_CONT: Computes the Hash along with the previous hash data
                                                                                     *                                      and saves for completion.
                                                                                     *                                      Here the Signature is not provided.
                                                                                     *          - #PH_EXCHANGE_BUFFER_LAST: Computes the Hash along with the previous hash data.
                                                                                     *                                      Here the Signature is provided.
                                                                                     */
        uint8_t bHashAlgo,                                                          /**< [In] The hashing algorithm to be used. Refer \ref phCryptoASym_CommonDefs_HashAlgos
                                                                                     *        "Hash Algorithms" for list for supported Algorithms.
                                                                                     */
        uint8_t * pMessage,                                                         /**< [In] Message to be signed. */
        uint16_t wMsgLen,                                                           /**< [In] Length of bytes in \b pMessage buffer. */
        uint8_t * pSign,                                                            /**< [Out] The signature of the message. The Signature will be in R
                                                                                     *         and S integer format. pSign = R data followed by S data.\n
                                                                                     *         Here R and S length should be based on the curve length.\n
                                                                                     *         Ex: If curve length is 256 bit then R and S length will be 32
                                                                                     *         bytes each.
                                                                                     */
        uint16_t * pSignLen                                                         /**< [Out] Length of bytes in \b pSign buffer. */
    );

/**
 * \brief Verifies the signature.
 *
 * \note
 *      - This interface needs to be called post using one of the below mentioned interfaces,
 *          - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
 *          - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
 *          - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
 *      - If the Message is small or needs to be verified in one call, then #PH_EXCHANGE_DEFAULT should be used for
 *        \b wOption parameter.
 *      - If the message is long enough and requires to be buffered, use #PH_EXCHANGE_BUFFER_FIRST,
 *        #PH_EXCHANGE_BUFFER_CONT and #PH_EXCHANGE_BUFFER_LAST options. The Signature will be utilized
 *        only when #PH_EXCHANGE_BUFFER_LAST is passed in \b wOption parameter.
 *      - If Hashing algorithm is \ref PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE "No-Hashing", then buffering options needs to be
 *        #PH_EXCHANGE_DEFAULT only. Other buffering options are not supported.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_KEY                      KeyPair not loaded or generated. Refer description notes for more information.
 * \retval #PH_ERR_UNSUPPORTED_HASH_ALGO    Hashing algorithm not supported. Refer \b bHashAlgo parameter description.
 * \retval #PH_ERR_INVALID_PARAMETER        If Hashing algorithm is \ref PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE "No-Hashing"
 *                                          and buffering options is not #PH_EXCHANGE_DEFAULT.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_Verify(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                           /**< [In] Buffering options combined with internal key context to use for verification.
                                                                                     *          - #PH_EXCHANGE_DEFAULT: Computes the Hash for the Message and
                                                                                     *                                  provides the verification based on the Signature.
                                                                                     *          - #PH_EXCHANGE_BUFFER_FIRST: Computes the Hash and saves for completion.
                                                                                     *                                       Here the Signature is not taken for verification.
                                                                                     *          - #PH_EXCHANGE_BUFFER_CONT: Computes the Hash along with the previous hash data
                                                                                     *                                      and saves for completion.
                                                                                     *                                      Here the Signature is not taken for verification.
                                                                                     *          - #PH_EXCHANGE_BUFFER_LAST: Computes the Hash along with the previous hash data.
                                                                                     *                                      Here the Signature is taken for verification.
                                                                                     */
        uint8_t bHashAlgo,                                                          /**< [In] The hashing algorithm to be used. Refer \ref phCryptoASym_CommonDefs_HashAlgos
                                                                                     *        "Hash Algorithms" for list for supported Algorithms.
                                                                                     */
        uint8_t * pMessage,                                                         /**< [In] Message to be verified. */
        uint16_t wMsgLen,                                                           /**< [In] Length of bytes in \b pMessage buffer. */
        uint8_t * pSign,                                                            /**< [In] The signature of the message. The Signature should be in R
                                                                                     *        and S integer format. pSign = R data followed by S data.\n
                                                                                     *        Here R and S length should be based on the curve length.\n
                                                                                     *        Ex: If curve length is 256 bit then R and S length will be 32
                                                                                     *        bytes each.
                                                                                     */
        uint16_t wSignLen                                                           /**< [In] Length of bytes in \b pSign buffer. */
    );

/**
 * \brief Computes the shared secret between current side private key and other side public key.
 * The computation used ECDH algorithm.
 *
 * \note
 *      - This interface needs to be called post using one of the below mentioned interfaces,
 *          - \ref phCryptoASym_ECC_GenerateKeyPair "Generate ECC KeyPair"
 *          - \ref phCryptoASym_ECC_LoadKey "Load ECC Key"
 *          - \ref phCryptoASym_ECC_LoadKeyDirect "Load ECC Direct Key"
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval #PH_ERR_KEY                      KeyPair not loaded or generated. Refer description notes for more information.
 * \retval #PH_ERR_UNSUPPORTED_CURVE_ID     Curve ID not supported. Refer \b wOption parameter description.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_ECC_SharedSecret(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wOption,                                                           /**< [In] The CurveID of the key thats available in \b pPublicKey buffer
                                                                                     *        combined with internal key context to use for shared secret computation.
                                                                                     *           - Refer \ref phCryptoASym_ECC_Defines_CurveID "Curve ID" for the Key to be loaded.
                                                                                     */
        uint8_t * pPublicKey,                                                       /**< [In] The other side's Public key. */
        uint16_t wPublicKeyLen,                                                     /**< [In] Length of bytes in \b pPublicKey buffer. */
        uint8_t * pSharedSecret,                                                    /**< [Out] Shared secret between current side's private key and other side's public key. */
        uint16_t * pSharedSecretLen                                                 /**< [Out] Length of bytes in \b pSharedSecret buffer. */
    );

/**
 * end of group phCryptoASym_ECC
 * @}
 */

/* CryptoASym Utility functions -------------------------------------------------------------------------------------------------------- */
/**
 * \defgroup phCryptoASym_Utility Commands_Utility
 * \brief Describes about the CryptoASym Utility functions.
 * @{
 */

/**
 * \brief Invalidate the currently loaded key.
 * Resets the key
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phCryptoASym_InvalidateKey(
        void * pDataParams                                                          /**< [In] Pointer to this layer's parameter structure */
    );

/**
 * \brief Returns the status code and respective message.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phCryptoASym_GetLastStatus(
        void * pDataParams,                                                         /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wStatusMsgLen,                                                     /**< [In] Size of bytes allocated for \b pStatusMsg parameter. */
        int8_t * pStatusMsg,                                                        /**< [Out] The equivalent status message for the information available in \b pStatusCode. */
        int32_t * pStatusCode                                                       /**< [Out] The status code returned by the underlying Crypto library. */
    );

/**
 * \brief Gets the size of the key based on the KeyPair and CurveID provided.
 *
 * \return Status code
 * \retval 0        : If any of the parameter value is not supported.
 * \retval Key Size : For the key provided as parameter information.
 */
uint16_t phCryptoASym_GetKeySize(
        uint16_t wKeyType,                                                          /**< [In] Refer \ref phCryptoASym_CommonDefs_KeyTypes "Key Types" for supported values. */
        uint16_t wKeyPair,                                                          /**< [In] Refer \ref phCryptoASym_CommonDefs_KeyPair "Key Pair" for supported values. */
        uint8_t bCurveID                                                            /**< [In] Refer \ref phCryptoASym_ECC_Defines_CurveID "Curve ID" for supported values. */
    );

/**
 * end of group phCryptoASym_Utility
 * @}
 */

/**
 * end of group phCryptoASym
 * @}
 */
#endif /* NXPBUILD__PH_CRYPTOASYM */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* PHCRYPTOASYM_H */
