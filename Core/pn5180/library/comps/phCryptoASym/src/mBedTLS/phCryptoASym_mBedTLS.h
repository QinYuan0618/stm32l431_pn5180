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
* mBedTLS specific ASymmetric Cryptography Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.13.00)
* $Date: $
*
*/

#ifndef PHCRYPTOASYM_MBEDTLS_H
#define PHCRYPTOASYM_MBEDTLS_H

#include <ph_Status.h>

#ifdef NXPBUILD__PH_CRYPTOASYM_MBEDTLS
#include <setjmp.h>

#include <ph_RefDefs.h>
#include <phCryptoASym.h>

#define TRY                                                                         \
    do                                                                              \
    {                                                                               \
        jmp_buf ex_buf__;                                                           \
        switch( setjmp(ex_buf__) )                                                  \
        {                                                                           \
            case 0:                                                                 \
                while (1)                                                           \
                {

#define CATCH(x)                                                                    \
                break;                                                              \
            case x:

#define FINALLY                                                                     \
                break;                                                              \
                }                                                                   \
            default:

#define END                                                                         \
        }                                                                           \
    } while(0);

#define END_EXT                                                                     \
                break;                                                              \
                }                                                                   \
            default:                                                                \
                break;                                                              \
        }                                                                           \
    } while(0);

#define THROW(x) longjmp(ex_buf__, x)

#define EXCEPTION           (1)
#define RDLIB_EXCEPTION     (2)
#define MBEDTLS_EXCEPTION   (3)

#define PH_CHECK_SUCCESS_FCT_EXT(Status, Fct)                                       \
    {                                                                               \
        (Status) = (Fct);                                                           \
        if (Status != 0)                                                            \
        {                                                                           \
            THROW(RDLIB_EXCEPTION);                                                 \
        }                                                                           \
    }

#define PH_CRYPTOASYM_CHECK_STATUS(DataParams, Status)                              \
    {                                                                               \
        if (Status != 0)                                                            \
        {                                                                           \
            DataParams->dwErrorCode = Status;                                       \
            THROW(MBEDTLS_EXCEPTION);                                               \
        }                                                                           \
    }

#define PH_CRYPTOASYM_INTERNAL_BUFFER_SIZE 256U

/* Validate KeyType */
#define PH_CRYPTOASYM_VALIDATE_KEYTYPE(Current, Expected)                           \
    if((Current) != (Expected))                                                     \
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_CRYPTOASYM)

/* Validate buffering options and hashing algorithm. */
#define PH_CRYPTOASYM_VALIDATE_BUFFER_OPTIONS(HashAlgo, Option)                     \
    if(((HashAlgo) == PH_CRYPTOASYM_HASH_ALGO_NOT_APPLICABLE) &&                    \
       (((Option) & PH_EXCHANGE_BUFFER_MASK) != PH_EXCHANGE_DEFAULT))               \
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_CRYPTOASYM)

#define PH_CRYPTOASYM_INT_BUFFER                    pDataParams->pBuffer
#define PH_CRYPTOASYM_INT_BUFFER_SIZE               pDataParams->wBufferSize

/* CryptoASym Utility functions -------------------------------------------------------------------------------------------------------- */
phStatus_t phCryptoASym_mBedTLS_InvalidateKey(phCryptoASym_mBedTLS_DataParams_t * pDataParams);

phStatus_t phCryptoASym_mBedTLS_GetLastStatus(phCryptoASym_mBedTLS_DataParams_t * pDataParams, uint16_t wStatusMsgLen, int8_t * pStatusMsg,
    int32_t * pStatusCode);

#endif /* NXPBUILD__PH_CRYPTOASYM_MBEDTLS */
#endif /* PHCRYPTOASYM_MBEDTLS_H */
