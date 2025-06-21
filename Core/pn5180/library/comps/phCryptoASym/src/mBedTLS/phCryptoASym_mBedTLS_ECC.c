/*----------------------------------------------------------------------------*/
/* Copyright 2021 - 2025 NXP                                                  */
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
* mBedTLS specific ECC ASymmetric Cryptography Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_ECC

#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_KEYSTORE_ASYM
#include <phKeyStore.h>
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

#include "phCryptoASym_mBedTLS.h"
#include "phCryptoASym_mBedTLS_ECC.h"

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH
#include "phCryptoASym_mBedTLS_Hash.h"
#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */

static phCryptoASym_mBedTLS_ECC_KeyPair stKeyPair_Ctx;

phStatus_t phCryptoASym_mBedTLS_ECC_GenerateKeyPair(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint8_t bCurveID)
{
    phStatus_t                  PH_MEMLOC_REM wStatus = 0;
    mbedtls_ecp_group           PH_MEMLOC_REM * pCtx_Group = NULL;
    mbedtls_ecp_point           PH_MEMLOC_REM * pCtx_Point = NULL;
    mbedtls_mpi                 PH_MEMLOC_REM * pCtx_Mpi = NULL;

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
    mbedtls_entropy_context     PH_MEMLOC_REM stCtx_Entropy;
    mbedtls_ctr_drbg_context    PH_MEMLOC_REM stCtx_Dbrg;
    char const                  PH_MEMLOC_REM * pPersoStr = "ECC_GenerateKeyPair";

#define PH_CRYPTOASYM_DBRG_CTX          &stCtx_Dbrg
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   mbedtls_ctr_drbg_random
#else
#define PH_CRYPTOASYM_DBRG_CTX          NULL
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   NULL
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

    /* Initialize the context. */
    phCryptoASym_mBedTLS_ECC_InitContext(pDataParams);

    /* Get the context to use. */
    pCtx_Group = PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP;
    pCtx_Point = PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT;
    pCtx_Mpi = PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI;

    /* Verify the Curves and get the curve context. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_SetCurveInfo(pDataParams, pCtx_Group, bCurveID));

    TRY
    {
        /* Clear the error status. */
        pDataParams->dwErrorCode = 0;

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        /* Initialize mbedTLS components. */
        mbedtls_entropy_init(&stCtx_Entropy);
        mbedtls_ctr_drbg_init(&stCtx_Dbrg);

        /* Seeding the random number generator */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_seed(&stCtx_Dbrg, mbedtls_entropy_func, &stCtx_Entropy,
            (unsigned char *) pPersoStr, strlen((const char *) pPersoStr)));
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

        /* Generating Key */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ecp_gen_keypair(pCtx_Group, pCtx_Mpi, pCtx_Point, PH_CRYPTOASYM_DBRG_CTX_RANDOM,
            PH_CRYPTOASYM_DBRG_CTX));

        /* Update information to DataParams. */
        pDataParams->wKeyType = PH_CRYPTOASYM_KEY_TYPE_ECC;
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        phCryptoASym_mBedTLS_InvalidateKey(pDataParams);
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    FINALLY
    {
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        /* Free the Used Contexts. */
        mbedtls_ctr_drbg_free(&stCtx_Dbrg);
        mbedtls_entropy_free(&stCtx_Entropy);
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */
    }
    END

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_ExportKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyBuffSize,
    uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wKey = 0;

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Extract the information from option. */
    wKey = (uint16_t) ( wOption & PH_CRYPTOASYM_KEYPAIR_MASK );

    /* Validate for availability of Key. */
    PH_CRYPTOASYM_VALIDATE_KEYTYPE(pDataParams->wKeyType, PH_CRYPTOASYM_KEY_TYPE_ECC);

    /* Export the Key. */
    switch(wKey)
    {
        case PH_CRYPTOASYM_PRIVATE_KEY:
            wStatus = phCryptoASym_mBedTLS_ECC_Export_PrivateKey(pDataParams, wKeyBuffSize, pCurveID, pKey, pKeyLen);
            break;

        case PH_CRYPTOASYM_PUBLIC_KEY:
            wStatus = phCryptoASym_mBedTLS_ECC_Export_PublicKey(pDataParams, wKeyBuffSize, pCurveID, pKey, pKeyLen);
            break;

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE, PH_COMP_CRYPTOASYM);
            break;
    }

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_LoadKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wPos)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

#ifdef NXPBUILD__PH_KEYSTORE_ASYM
    uint16_t    PH_MEMLOC_REM wOption_Tmp = 0;
    uint16_t    PH_MEMLOC_REM wKeyType_Tmp = 0;
    uint16_t    PH_MEMLOC_REM wBuffLen = 0;
    uint16_t    PH_MEMLOC_REM wKeyPair = 0;
    uint8_t     PH_MEMLOC_REM bCurveID = 0;

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Extract the information from option. */
    wKeyPair = (uint16_t) (wOption & PH_CRYPTOASYM_KEYPAIR_MASK);

    /* Clear temporary buffer. */
    (void) memset(PH_CRYPTOASYM_INT_BUFFER, 0x00, PH_CRYPTOASYM_INT_BUFFER_SIZE);

    /* Load the required keys. */
    switch(wKeyPair)
    {
        case PH_CRYPTOASYM_PRIVATE_KEY:
            /* Get the Private Key from KeyStore. */
            wStatus = phKeyStore_GetKeyASym(pDataParams->pKeyStoreDataParams, wKeyNo, wPos, PH_CRYPTOASYM_PRIVATE_KEY, &wKeyType_Tmp,
                &bCurveID, PH_CRYPTOASYM_INT_BUFFER, &wBuffLen);

            /* Load the Private Key is stored in KeyStore. */
            if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            {
                /* Load the Private Key. */
                PH_CRYPTOASYM_VALIDATE_KEYTYPE(wKeyType_Tmp, PH_CRYPTOASYM_KEY_TYPE_ECC);

                /* Frame the Options. */
                wOption_Tmp = (uint16_t) (bCurveID | wOption);
                PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_LoadKeyDirect(pDataParams, wOption_Tmp, PH_CRYPTOASYM_INT_BUFFER,
                    wBuffLen));
            }
            break;

        case PH_CRYPTOASYM_PUBLIC_KEY:
            /* Get the Public Key from KeyStore. */
            wStatus = phKeyStore_GetKeyASym(pDataParams->pKeyStoreDataParams, wKeyNo, wPos, PH_CRYPTOASYM_PUBLIC_KEY, &wKeyType_Tmp,
                &bCurveID, PH_CRYPTOASYM_INT_BUFFER, &wBuffLen);

            /* Load the Public Key is stored in KeyStore. */
            if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            {
                /* KeyType should match. */
                PH_CRYPTOASYM_VALIDATE_KEYTYPE(wKeyType_Tmp, PH_CRYPTOASYM_KEY_TYPE_ECC);

                /* Load the Public Key. */
                wOption_Tmp = (uint16_t) (bCurveID | wOption);
                PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_LoadKeyDirect(pDataParams, wOption_Tmp, PH_CRYPTOASYM_INT_BUFFER,
                    wBuffLen));
            }
            break;

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE, PH_COMP_CRYPTOASYM);
            break;
    }

    /* Validate the Status. */
    PH_CHECK_SUCCESS(wStatus);

#else
    /* Satisfy compiler */
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(wOption);
    PH_UNUSED_VARIABLE(wKeyNo);
    PH_UNUSED_VARIABLE(wPos);

    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_CRYPTOASYM);
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_LoadKeyDirect(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pKey,
    uint16_t wKeyLen)
{
    phStatus_t              PH_MEMLOC_REM wStatus = 0;
    uint16_t                PH_MEMLOC_REM wKey = 0;
    uint8_t                 PH_MEMLOC_REM bCurveID = 0;
    mbedtls_ecp_group       PH_MEMLOC_REM * pCtx_Group = NULL;
    mbedtls_ecp_point       PH_MEMLOC_REM * pCtx_Point = NULL;
    mbedtls_mpi             PH_MEMLOC_REM * pCtx_Mpi = NULL;

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Extract the information from option. */
    wKey = (uint16_t) ( wOption & PH_CRYPTOASYM_KEYPAIR_MASK );
    bCurveID = (uint8_t) ( wOption & PH_CRYPTOASYM_CURVE_ID_MASK);

    /* Initialize the context. */
    phCryptoASym_mBedTLS_ECC_InitContext(pDataParams);

    /* Get the context to use. */
    pCtx_Group = PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP;
    pCtx_Point = PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT;
    pCtx_Mpi = PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI;

    /* Load the Key. */
    switch(wKey)
    {
        case PH_CRYPTOASYM_PRIVATE_KEY:
            wStatus = phCryptoASym_mBedTLS_ECC_Load_PrivateKey(pDataParams, pCtx_Group, pCtx_Mpi, bCurveID, pKey, wKeyLen);
            break;

        case PH_CRYPTOASYM_PUBLIC_KEY:
            /* Validate if its in uncompressed point notation. */
            if(pKey[0] != 0x04)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOASYM);

            wStatus = phCryptoASym_mBedTLS_ECC_Load_PublicKey(pDataParams, pCtx_Group, pCtx_Point, bCurveID, pKey, wKeyLen);
            break;

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_KEY_PAIR_TYPE, PH_COMP_CRYPTOASYM);
            break;
    }

    /* Update KeyType. */
    if(( wStatus & PH_ERR_MASK ) == PH_ERR_SUCCESS)
    {
        pDataParams->wKeyType = PH_CRYPTOASYM_KEY_TYPE_ECC;
    }

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Sign(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage,
    uint16_t wMsgLen, uint8_t * pSign, uint16_t * pSignLen)
{
    phStatus_t                  PH_MEMLOC_REM wStatus = 0;
    mbedtls_ecp_group           PH_MEMLOC_REM * pCtx_Group = NULL;
    mbedtls_mpi                 PH_MEMLOC_REM * pCtx_Mpi = NULL;
    mbedtls_mpi                 PH_MEMLOC_REM stCtx_Sig_R;
    mbedtls_mpi                 PH_MEMLOC_REM stCtx_Sig_S;
    uint16_t                    PH_MEMLOC_REM wKeyLen = 0;
    uint16_t                    PH_MEMLOC_REM wHashLen = 0;
    uint8_t                     PH_MEMLOC_REM aHash[64];

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
    mbedtls_entropy_context     PH_MEMLOC_REM stCtx_Entropy;
    mbedtls_ctr_drbg_context    PH_MEMLOC_REM stCtx_Dbrg;
    char const                  PH_MEMLOC_REM * pPersoStr = "ECC_Signing";

#define PH_CRYPTOASYM_DBRG_CTX          &stCtx_Dbrg
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   mbedtls_ctr_drbg_random
#else
#define PH_CRYPTOASYM_DBRG_CTX          NULL
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   NULL
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

    /* Validate KeyType. */
    PH_CRYPTOASYM_VALIDATE_KEYTYPE(pDataParams->wKeyType, PH_CRYPTOASYM_KEY_TYPE_ECC);

    /* Validate buffering options and hashing algorithm. */
    PH_CRYPTOASYM_VALIDATE_BUFFER_OPTIONS(bHashAlgo, wOption);

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Clear local buffer. */
    (void) memset(aHash, 0x00, sizeof(aHash));

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH
    if(bHashAlgo != PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE)
    {
        /* Generate the Hash for the message to be signed. */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ComputeHash(pDataParams, wOption, bHashAlgo, pMessage,
            wMsgLen, aHash, &wHashLen));

        /* Return if Buffering is not Last or Default. */
        if(wOption & PH_EXCHANGE_BUFFERED_BIT)
            return PH_ERR_SUCCESS;
    }
    else
#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */
    {
        (void) memcpy(aHash, pMessage, wMsgLen);
        wHashLen = wMsgLen;
    }

    /* Get the context to use. */
    pCtx_Group = PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP;
    pCtx_Mpi = PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI;

    TRY
    {
        /* Initialize mbedTLS components. */
        mbedtls_mpi_init(&stCtx_Sig_R);
        mbedtls_mpi_init(&stCtx_Sig_S);

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        mbedtls_entropy_init(&stCtx_Entropy);
        mbedtls_ctr_drbg_init(&stCtx_Dbrg);

        /* Seeding the random number generator */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_seed(&stCtx_Dbrg, mbedtls_entropy_func,
            &stCtx_Entropy, (unsigned char *) pPersoStr, strlen((const char *) pPersoStr)));
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

        /* Sign the Hashed message. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ecdsa_sign(pCtx_Group, &stCtx_Sig_R, &stCtx_Sig_S, pCtx_Mpi, aHash,
            wHashLen, PH_CRYPTOASYM_DBRG_CTX_RANDOM, PH_CRYPTOASYM_DBRG_CTX));

        /* Compute the maximum length to write including trailing byte. */
        wKeyLen = phCryptoASym_mBedTLS_ECC_GetKeySize(PH_CRYPTOASYM_PRIVATE_KEY, PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID);

        /* Copy Signature R data to Buffer. */
        *pSignLen = 0U;
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(&stCtx_Sig_R, &pSign[*pSignLen], wKeyLen));
        *pSignLen = (uint16_t) (*pSignLen + wKeyLen);

        /* Copy Signature S data to Buffer. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(&stCtx_Sig_S, &pSign[*pSignLen], wKeyLen));
        *pSignLen = (uint16_t) (*pSignLen + wKeyLen);
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    FINALLY
    {
        /* Free the Used Contexts. */
        mbedtls_mpi_free(&stCtx_Sig_R);
        mbedtls_mpi_free(&stCtx_Sig_S);

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        mbedtls_ctr_drbg_free(&stCtx_Dbrg);
        mbedtls_entropy_free(&stCtx_Entropy);
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */
    }
    END

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Verify(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t bHashAlgo, uint8_t * pMessage,
    uint16_t wMsgLen, uint8_t * pSign, uint16_t wSignLen)
{
    phStatus_t                  PH_MEMLOC_REM wStatus = 0;
    int32_t                     PH_MEMLOC_REM dwRetCode = 0;
    uint8_t                     PH_MEMLOC_REM aHash[64];
    uint16_t                    PH_MEMLOC_REM wHashLen = 0;
    uint16_t                    PH_MEMLOC_REM wMPI_Len = 0;
    mbedtls_ecp_group           PH_MEMLOC_REM * pCtx_Group = NULL;
    mbedtls_ecp_point           PH_MEMLOC_REM * pCtx_Point = NULL;
    mbedtls_mpi                 PH_MEMLOC_REM stCtx_Sig_R;
    mbedtls_mpi                 PH_MEMLOC_REM stCtx_Sig_S;
    /* Validate KeyType. */
    PH_CRYPTOASYM_VALIDATE_KEYTYPE(pDataParams->wKeyType, PH_CRYPTOASYM_KEY_TYPE_ECC);

    /* Validate buffering options and hashing algorithm. */
    PH_CRYPTOASYM_VALIDATE_BUFFER_OPTIONS(bHashAlgo, wOption);

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Clear local buffer. */
    (void) memset(aHash, 0x00, sizeof(aHash));

#ifdef NXPBUILD__PH_CRYPTOASYM_HASH
    if(bHashAlgo != PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE)
    {
        /* Generate the Hash for the message to be signed. */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ComputeHash(pDataParams, wOption, bHashAlgo, pMessage, wMsgLen,
            aHash, &wHashLen));

        /* Return if Buffering is not Last or Default. */
        if(wOption & PH_EXCHANGE_BUFFERED_BIT)
            return PH_ERR_SUCCESS;
    }
    else
#endif /* NXPBUILD__PH_CRYPTOASYM_HASH */
    {
        (void) memcpy(aHash, pMessage, wMsgLen);
        wHashLen = wMsgLen;
    }

    /* Get the context to use. */
    pCtx_Group = PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP;
    pCtx_Point = PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT;

    TRY
    {
        /* Initialize mbedTLS components. */
        mbedtls_mpi_init(&stCtx_Sig_R);
        mbedtls_mpi_init(&stCtx_Sig_S);

        /* Convert Signature R and S to MPI Context. */
        wMPI_Len = (uint16_t) ( wSignLen / 2 );
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_read_binary(&stCtx_Sig_R, &pSign[0], wMPI_Len));
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_read_binary(&stCtx_Sig_S, &pSign[wMPI_Len], wMPI_Len));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);

        /* Free the Used Contexts. */
        mbedtls_mpi_free(&stCtx_Sig_R);
        mbedtls_mpi_free(&stCtx_Sig_S);
    }
    END_EXT

    /* Return the Status in case of Failure. */
    PH_CHECK_SUCCESS(wStatus);

    TRY
    {
        /* Verify the message. */
        dwRetCode = mbedtls_ecdsa_verify(pCtx_Group, aHash, wHashLen, pCtx_Point, &stCtx_Sig_R, &stCtx_Sig_S);
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, dwRetCode);
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_VERIFICATION_FAILED, PH_COMP_CRYPTOASYM);
    }
    FINALLY
    {
        /* Free the Used Contexts. */
        mbedtls_mpi_free(&stCtx_Sig_R);
        mbedtls_mpi_free(&stCtx_Sig_S);
    }
    END

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_SharedSecret(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pPublicKey,
    uint16_t wPublicKeyLen, uint8_t * pSharedSecret, uint16_t * pSharedSecretLen)
{
    phStatus_t                  PH_MEMLOC_REM wStatus = 0;
    uint16_t                    PH_MEMLOC_REM wKeyLen = 0;
    uint8_t                     PH_MEMLOC_REM bCurveID = 0;
    mbedtls_mpi                 PH_MEMLOC_REM stCtx_SharedSecret;
    mbedtls_ecp_group           PH_MEMLOC_REM stCtx_Group;
    mbedtls_ecp_point           PH_MEMLOC_REM stCtx_Point;
    mbedtls_mpi                 PH_MEMLOC_REM * pCtx_PrivateKey = NULL;

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
    mbedtls_entropy_context     PH_MEMLOC_REM stCtx_Entropy;
    mbedtls_ctr_drbg_context    PH_MEMLOC_REM stCtx_Dbrg;
    char const                  PH_MEMLOC_REM * pPersoStr = "ECC_SharedSecret";

#define PH_CRYPTOASYM_DBRG_CTX          &stCtx_Dbrg
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   mbedtls_ctr_drbg_random
#else
#define PH_CRYPTOASYM_DBRG_CTX          NULL
#define PH_CRYPTOASYM_DBRG_CTX_RANDOM   NULL
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

    /* Extract the information from option. */
    bCurveID = (uint8_t) (wOption & PH_CRYPTOASYM_CURVE_ID_MASK);

    /* Validate KeyType. */
    PH_CRYPTOASYM_VALIDATE_KEYTYPE(pDataParams->wKeyType, PH_CRYPTOASYM_KEY_TYPE_ECC);

    /* Clear the error status. */
    pDataParams->dwErrorCode = 0;

    /* Extract the information from option. */
    pCtx_PrivateKey = PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI;

    TRY
    {
        /* Load Public Key.  */
#ifdef MBEDTLS_ECP_C
        mbedtls_ecp_group_init(&stCtx_Group);
        mbedtls_ecp_point_init(&stCtx_Point);
#endif /* MBEDTLS_ECP_C */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_Load_PublicKey(pDataParams, &stCtx_Group, &stCtx_Point, bCurveID, pPublicKey,
            wPublicKeyLen));

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        /* Seeding the random number generator */
        mbedtls_entropy_init(&stCtx_Entropy);
        mbedtls_ctr_drbg_init(&stCtx_Dbrg);
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ctr_drbg_seed(&stCtx_Dbrg, mbedtls_entropy_func,
            &stCtx_Entropy, (unsigned char *) pPersoStr, strlen((const char *) pPersoStr)));
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */

        /* Compute Shared secret. */
        mbedtls_mpi_init(&stCtx_SharedSecret);
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ecdh_compute_shared(&stCtx_Group, &stCtx_SharedSecret, &stCtx_Point,
            pCtx_PrivateKey, PH_CRYPTOASYM_DBRG_CTX_RANDOM, PH_CRYPTOASYM_DBRG_CTX));

        /* Compute the maximum length to write including trailing byte. */
        wKeyLen = phCryptoASym_mBedTLS_ECC_GetKeySize(PH_CRYPTOASYM_PRIVATE_KEY, PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID);

        /* Write the shared secret to buffer. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(&stCtx_SharedSecret, pSharedSecret, wKeyLen));
        *pSharedSecretLen = wKeyLen;
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    FINALLY
    {
        /* Clear the utilized context. */
#ifdef MBEDTLS_ECP_C
        mbedtls_ecp_group_free(&stCtx_Group);
        mbedtls_ecp_point_free(&stCtx_Point);
#endif /* MBEDTLS_ECP_C */
        mbedtls_mpi_free(&stCtx_SharedSecret);

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642)
        mbedtls_ctr_drbg_free(&stCtx_Dbrg);
        mbedtls_entropy_free(&stCtx_Entropy);
#endif /* !defined(MBEDTLS_NO_PLATFORM_ENTROPY) || !defined(NXPBUILD__PHHAL_HW_PN7642) */
    }
    END

    return wStatus;
}

uint16_t phCryptoASym_mBedTLS_ECC_GetKeySize(uint16_t wKeyPair, uint8_t bCurveID)
{
    switch(wKeyPair)
    {
        case PH_CRYPTOASYM_PRIVATE_KEY:
            switch(bCurveID)
            {
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP192R1:
                    return 24U;
                    break;
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP224R1:
                    return 28U;
                    break;
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP256R1:
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1:
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */
                    return 32U;
                    break;

#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP384R1:
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1:
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */
                    return 48U;
                    break;

                default:
                    break;
            }
            break;

        case PH_CRYPTOASYM_PUBLIC_KEY:
            switch(bCurveID)
            {
#ifdef MBEDTLS_ECP_DP_SECP192R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP192R1:
                    return (uint16_t) (48U + 1U /* Un-Compressed format notation */);
                    break;
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP224R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP224R1:
                    return (uint16_t) (56U + 1U /* Un-Compressed format notation */);
                    break;
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */

#ifdef MBEDTLS_ECP_DP_SECP256R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP256R1:
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#ifdef MBEDTLS_ECP_DP_BP256R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1:
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */
                    return (uint16_t) (64U + 1U /* Un-Compressed format notation */);
                    break;

#ifdef MBEDTLS_ECP_DP_SECP384R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_SECP384R1:
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#ifdef MBEDTLS_ECP_DP_BP384R1_ENABLED
                case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1:
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */
                    return (uint16_t) (96U + 1U /* Un-Compressed format notation */);
                    break;

                default:
                    break;
            }
            break;

        default:
            break;
    }

    return 0;
}

void phCryptoASym_mBedTLS_ECC_InitContext(phCryptoASym_mBedTLS_DataParams_t * pDataParams)
{
    /* Initialize the group context */
    if(pDataParams->pCtx == NULL)
    {
#ifdef MBEDTLS_ECP_C
        mbedtls_ecp_group_init(&stKeyPair_Ctx.stGroup);
        mbedtls_ecp_point_init(&stKeyPair_Ctx.stPoint);
        mbedtls_mpi_init(&stKeyPair_Ctx.stMpi);
#endif /* MBEDTLS_ECP_C */

        pDataParams->pCtx = &stKeyPair_Ctx;
    }
}

phStatus_t phCryptoASym_mBedTLS_ECC_ValidateCurveID(mbedtls_ecp_group * pCtx_Group, uint8_t bCurveID)
{
    phStatus_t                          PH_MEMLOC_REM wStatus = 0;

    /* Check if the Context consist of a Curve ID. */
    if(pCtx_Group->id != PH_CRYPTOASYM_CURVE_ID_NONE)
    {
        /* Validate Curve ID's */
        switch(bCurveID)
        {
#ifdef PH_CRYPTOASYM_CURVE_ID_SECP192R1
            case PH_CRYPTOASYM_CURVE_ID_SECP192R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_SECP192R1 */

#ifdef PH_CRYPTOASYM_CURVE_ID_SECP224R1
            case PH_CRYPTOASYM_CURVE_ID_SECP224R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_SECP224R1 */

#ifdef PH_CRYPTOASYM_CURVE_ID_SECP256R1
            case PH_CRYPTOASYM_CURVE_ID_SECP256R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_SECP256R1 */

#ifdef PH_CRYPTOASYM_CURVE_ID_SECP384R1
            case PH_CRYPTOASYM_CURVE_ID_SECP384R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_SECP384R1 */

#ifdef PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1
            case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_BRAINPOOL256R1 */

#ifdef PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1
            case PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1:
#endif /* PH_CRYPTOASYM_CURVE_ID_BRAINPOOL384R1 */
                /* Nothing to do here. */
                break;

            default:
                wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_CURVE_ID, PH_COMP_CRYPTOASYM);
                break;
        }
    }

    /* Check the current Curve ID. */
    else
    {
        /* Nothing to do here. */
    }

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_SetCurveInfo(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group, uint8_t bCurveID)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

#ifdef MBEDTLS_ECP_C
    const mbedtls_ecp_curve_info    PH_MEMLOC_REM * pCurveInfo = NULL;

    pCurveInfo = mbedtls_ecp_curve_info_from_grp_id((mbedtls_ecp_group_id) bCurveID);
    if(pCurveInfo == NULL)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_CURVE_ID, PH_COMP_CRYPTOASYM);
    }
    else
    {
        TRY
        {
            /* Update the Group ID to use. */
            PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_ecp_group_load(pCtx_Group, pCurveInfo->grp_id));
        }
        CATCH(MBEDTLS_EXCEPTION)
        {
            phCryptoASym_mBedTLS_InvalidateKey(pDataParams);
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
        }
        END_EXT
    }
#endif /* MBEDTLS_ECP_C */

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Export_PrivateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyBuffSize,
    uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen)
{
    phStatus_t              PH_MEMLOC_REM wStatus = 0;
    mbedtls_mpi             PH_MEMLOC_REM * pCtx_Mpi = NULL;

    /* Get the context to use. */
    pCtx_Mpi = PH_CRYPTOASYM_MBEDTLS_ECC_GET_MPI;
    (void) memset(pKey, 0x00, wKeyBuffSize);

    TRY
    {
        *pKeyLen = phCryptoASym_mBedTLS_ECC_GetKeySize(PH_CRYPTOASYM_PRIVATE_KEY, PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID);
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(pCtx_Mpi, pKey, *pKeyLen));

        /* Update Curve ID. */
        *pCurveID = PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID;
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Export_PublicKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wKeyBuffSize,
    uint8_t * pCurveID, uint8_t * pKey, uint16_t * pKeyLen)
{
    phStatus_t              PH_MEMLOC_REM wStatus = 0;
    uint16_t                PH_MEMLOC_REM wKeyLen = 0;
    mbedtls_ecp_group       PH_MEMLOC_REM * pCtx_Group;
    mbedtls_ecp_point       PH_MEMLOC_REM * pCtx_Point;

    /* Get the context to use. */
    pCtx_Group = PH_CRYPTOASYM_MBEDTLS_ECC_GET_GROUP;
    pCtx_Point = PH_CRYPTOASYM_MBEDTLS_ECC_GET_POINT;
    (void) memset(pKey, 0x00, wKeyBuffSize);

    /* To resolve warning */
    PH_UNUSED_VARIABLE(pCtx_Group);

    TRY
    {
        pKey[0] = 0x04U;
        (*pKeyLen)++;

        /* Compute the maximum length to write including trailing byte. */
        wKeyLen = phCryptoASym_mBedTLS_ECC_GetKeySize(PH_CRYPTOASYM_PRIVATE_KEY, PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID);

        /* Get the X point. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(&pCtx_Point->X, &pKey[*pKeyLen], wKeyLen));
        *pKeyLen = (uint16_t) (*pKeyLen + wKeyLen);

        /* Get the Y point. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_write_binary(&pCtx_Point->Y, &pKey[*pKeyLen], wKeyLen));
        *pKeyLen = (uint16_t) (*pKeyLen + wKeyLen);

        /* Update Curve ID. */
        *pCurveID = PH_CRYPTOASYM_MBEDTLS_ECC_GET_CURVE_ID;
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Load_PrivateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group,
    mbedtls_mpi * pCtx_Mpi, uint8_t bCurveID, uint8_t * pKey, uint16_t wKeyLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Validate CurveID. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_ValidateCurveID(pCtx_Group, bCurveID));

    /* Update the Curve information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_SetCurveInfo(pDataParams, pCtx_Group, bCurveID));

#ifdef MBEDTLS_ECP_C
    TRY
    {
        /* Copy private key. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_read_binary(pCtx_Mpi, pKey, wKeyLen));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        phCryptoASym_mBedTLS_InvalidateKey(pDataParams);
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT
#else
    /* Satisfy the compiler. */
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(pCtx_Mpi);
    PH_UNUSED_VARIABLE(pKey);
    PH_UNUSED_VARIABLE(wKeyLen);
#endif /* MBEDTLS_ECP_C */

    return wStatus;
}

phStatus_t phCryptoASym_mBedTLS_ECC_Load_PublicKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams, mbedtls_ecp_group * pCtx_Group,
    mbedtls_ecp_point * pCtx_Point, uint8_t bCurveID, uint8_t * pKey, uint16_t wKeyLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Validate CurveID. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_ValidateCurveID(pCtx_Group, bCurveID));

    /* Update the Curve information. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoASym_mBedTLS_ECC_SetCurveInfo(pDataParams, pCtx_Group, bCurveID));

    TRY
    {
        /* Initialize the mpi context. */
        mbedtls_mpi_init(&pCtx_Point->X);
        mbedtls_mpi_init(&pCtx_Point->Y);
        mbedtls_mpi_init(&pCtx_Point->Z);

        /* Remove the uncompressed point notation. */
        pKey++;
        wKeyLen--;

        /* Copy PublicKey's X component. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_read_binary(&pCtx_Point->X, &pKey[0], wKeyLen / 2));

        /* Copy PublicKey's Y component. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_read_binary(&pCtx_Point->Y, &pKey[wKeyLen / 2], wKeyLen / 2));

        /* Set the integer value. */
        PH_CRYPTOASYM_CHECK_STATUS(pDataParams, mbedtls_mpi_lset(&pCtx_Point->Z, 1));
    }
    CATCH(MBEDTLS_EXCEPTION)
    {
        phCryptoASym_mBedTLS_InvalidateKey(pDataParams);
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTERNAL_ERROR, PH_COMP_CRYPTOASYM);
    }
    END_EXT

    return wStatus;
}

#endif /* NXPBUILD__PH_CRYPTOASYM_ECC */
