/*----------------------------------------------------------------------------*/
/* Copyright 2017-2020, 2024, 2025 NXP                                        */
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
 * Internal functions of both Software and SamNonX implementation of ICode application layer.
 * $Author:
 * $Revision:
 * $Date:
 *
 */

#ifndef PHALICODE_INT_H
#define PHALICODE_INT_H

#include <ph_Status.h>

/** add cmd: ICode product's command codes. */
#define PHAL_ICODE_CMD_INVENTORY                                    0x01U    /**< �̴� */
#define PHAL_ICODE_CMD_STAY_QUIET                                   0x02U    /**< ʹ����ı�ǩ���뾲Ĭģʽ */
#define PHAL_ICODE_CMD_SELECT                                       0x25U

/** ICode product's command codes. */
#define PHAL_ICODE_CMD_READ_SINGLE_BLOCK                            0x20U    /**< ICode command code for ReadSingleBlock command. */
#define PHAL_ICODE_CMD_WRITE_SINGLE_BLOCK                           0x21U    /**< ICode command code for WriteSingleBlock command. */
#define PHAL_ICODE_CMD_LOCK_BLOCK                                   0x22U    /**< ICode command code for LockBlock command. */
#define PHAL_ICODE_CMD_READ_MULTIPLE_BLOCKS                         0x23U    /**< ICode command code for ReadMultipleBlock command. */
#define PHAL_ICODE_CMD_WRITE_AFI                                    0x27U    /**< ICode command code for WriteAFI command. */
#define PHAL_ICODE_CMD_LOCK_AFI                                     0x28U    /**< ICode command code for LockAFI command. */
#define PHAL_ICODE_CMD_WRITE_DSFID                                  0x29U    /**< ICode command code for WriteDSFID command. */
#define PHAL_ICODE_CMD_LOCK_DSFID                                   0x2AU    /**< ICode command code for LockDSFID command. */
#define PHAL_ICODE_CMD_GET_SYSTEM_INFORMATION                       0x2BU    /**< ICode command code for GetSystemInformation command. */
#define PHAL_ICODE_CMD_GET_MULTIPLE_BLOCK_SECURITY_STATUS           0x2CU    /**< ICode command code for GetMultipleBlockSecurityStatus command. */
#define PHAL_ICODE_CMD_FAST_READ_MULTIPLE_BLOCKS                    0x2DU    /**< ICODE command code for FastReadMultipleBlocks command. */
#define PHAL_ICODE_CMD_EXTENDED_READ_SINGLE_BLOCK                   0x30U    /**< ICode command code for ExtendedReadSingleBlock command. */
#define PHAL_ICODE_CMD_EXTENDED_WRITE_SINGLE_BLOCK                  0x31U    /**< ICode command code for ExtendedWriteSingleBlock command. */
#define PHAL_ICODE_CMD_EXTENDED_LOCK_BLOCK                          0x32U    /**< ICode command code for ExtendedLockSingleBlock command. */
#define PHAL_ICODE_CMD_EXTENDED_READ_MULTIPLE_BLOCKS                0x33U    /**< ICode command code for ExtendedReadMultipleBlock command. */
#define PHAL_ICODE_CMD_AUTHENTICATE                                 0x35U    /**< ICODE command code for Authenticate command. */
#define PHAL_ICODE_CMD_CHALLENGE                                    0x39U    /**< ICODE command code for Challenge command. */
#define PHAL_ICODE_CMD_READ_BUFFER                                  0x3AU    /**< ICODE command code for Read Buffer command. */
#define PHAL_ICODE_CMD_EXTENDED_GET_SYSTEM_INFORMATION              0x3BU    /**< ICODE command code for ExtendedGetSystemInformation command. */
#define PHAL_ICODE_CMD_EXTENDED_GET_MULTIPLE_BLOCK_SECURITY_STATUS  0x3CU    /**< ICODE command code for ExtendedGetMultipleBlockSecurityStatus command. */
#define PHAL_ICODE_CMD_EXTENDED_FAST_READ_MULTIPLE_BLOCKS           0x3DU    /**< ICODE command code for ExtendedFastReadMultipleBlocks command. */
#define PHAL_ICODE_CMD_SET_EAS                                      0xA2U    /**< ICode command code for SetEAS command. */
#define PHAL_ICODE_CMD_RESET_EAS                                    0xA3U    /**< ICode command code for ResetEAS command. */
#define PHAL_ICODE_CMD_LOCK_EAS                                     0xA4U    /**< ICode command code for LockEAS command. */
#define PHAL_ICODE_CMD_EAS_ALARM                                    0xA5U    /**< ICode command code for EASAlarm command. */
#define PHAL_ICODE_CMD_PASSWORD_PROTECT_EAS_AFI                     0xA6U    /**< ICode command code for PasswordProtectEAS command. */
#define PHAL_ICODE_CMD_WRITE_EAS_ID                                 0xA7U    /**< ICode command code for WriteEASID command. */
#define PHAL_ICODE_CMD_READ_EPC                                     0xA8U    /**< ICode command code for ReadEPC command. */
#define PHAL_ICODE_CMD_GET_NXP_SYSTEM_INFORMATION                   0xABU    /**< ICode command code for GetNXPSystemInformation command. */
#define PHAL_ICODE_CMD_GET_RANDOM_NUMBER                            0xB2U    /**< ICode command code for GetRandomNumber command. */
#define PHAL_ICODE_CMD_SET_PASSWORD                                 0xB3U    /**< ICode command code for SetPassword command. */
#define PHAL_ICODE_CMD_WRITE_PASSWORD                               0xB4U    /**< ICode command code for WritePassword command. */
#define PHAL_ICODE_CMD_LOCK_PASSWORD                                0xB5U    /**< ICode command code for LockPassword command. */
#define PHAL_ICODE_CMD_PROTECT_PAGE                                 0xB6U    /**< ICode command code for ProtectPage command. */
#define PHAL_ICODE_CMD_LOCK_PAGE_PROTECTION_CONDITION               0xB7U    /**< ICode command code for LockPageProtectionCondition command. */
#define PHAL_ICODE_CMD_GET_MULTIPLE_BLOCK_PROTECTION_STATUS         0xB8U    /**< ICode command code for GetMultipleBlockProtectionStatus command. */
#define PHAL_ICODE_CMD_DESTROY                                      0xB9U    /**< ICode command code for Destroy command. */
#define PHAL_ICODE_CMD_ENABLE_PRIVACY                               0xBAU    /**< ICode command code for EnablePrivacy command. */
#define PHAL_ICODE_CMD_64_BIT_PASSWORD_PROTECTION                   0xBBU    /**< ICode command code for 64-BitPasswordProtection command. */
#define PHAL_ICODE_CMD_READ_SIGNATURE                               0xBDU    /**< ICode command code for ReadSignature command. */
#define PHAL_ICODE_CMD_READ_CONFIG                                  0xC0U    /**< ICODE command code for Read Config command. */
#define PHAL_ICODE_CMD_WRITE_CONFIG                                 0xC1U    /**< ICODE command code for Write Config command. */
#define PHAL_ICODE_CMD_PICK_RANDOM_ID                               0xC2U    /**< ICODE command code for Pick Random Id command. */
#define PHAL_ICODE_CMD_READ_TT                                      0xC4U    /**< ICODE command code for ReadTT command. */
#define PHAL_ICODE_CMD_PARAMETER_REQUEST                            0xD0U    /**< ICODE command code for Parameter Request command. */
#define PHAL_ICODE_CMD_PARAMETER_SELECT                             0xD1U    /**< ICODE command code for Parameter Select command. */
#define PHAL_ICODE_CMD_READ_SRAM                                    0xD2U    /**< ICODE command code for Read SRAM command. */
#define PHAL_ICODE_CMD_WRITE_SRAM                                   0xD3U    /**< ICODE command code for Write SRAM command. */
#define PHAL_ICODE_CMD_I2CM_WRITE                                   0xD4U   /**< ICODE command code for I2CM Write command. */
#define PHAL_ICODE_CMD_I2CM_READ                                    0xD5U   /**< ICODE command code for I2CM Read command. */
#define PHAL_ICODE_RANDOM_NUMBER_SIZE                               0x0AU   /**< Authenticate and Challenge Random number size. */
#define PHAL_ICODE_BLOCK_SIZE                                       4U      /**< Bytes available in one block. */
#define PHAL_ICODE_MAX_BLOCKS                                       256U    /**< Maximum blocks supported by I15693 specification. */
#define PHAL_ICODE_MAX_BLOCKS_CM1_OPTION_FLAG_NOT_SET               60U     /**< Maimum block data that can be read using CM1 reader when Option flag is not set. */
#define PHAL_ICODE_MAX_BLOCKS_CM1_OPTION_FLAG_SET                   40U     /**< Maimum block data that can be read using CM1 reader when Option flag is set. */
#define PHAL_ICODE_MAX_I2C_DATA_SIZE                                256U    /**< Maximum data size that can be transmitted or received using I2C Transparent Channel commands. */

/** Authenticate constants for Tag and mutual authentication. */
#define PHAL_ICODE_CONST_TAM1                                       0x96C5U /**< Macro value for Tag authentication 1 constant value. */
#define PHAL_ICODE_CONST_MAM1                                       0xDA83U /**< Macro value for Mutual authentication 1 constant value. */
#define PHAL_ICODE_CONST_MAM2                                       0xDA80U /**< Macro value for Mutual authentication 2 constant value. */

#define PHAL_ICODE_AUTHPROC_TAM                                     0x00U   /**< Macro value for authentication option as Tag Authentication. */
#define PHAL_ICODE_AUTHPROC_MAM                                     0x02U   /**< Macro value for authentication option as Mutual Authentication. */
#define PHAL_ICODE_CSI_AES                                          0x00U   /**< Macro to represent the value of the CSI (AES Crypto Suite). */
#define PHAL_ICODE_CSI_DH                                           0xD2U   /**< Macro to represent the value of the CSI (Diffie-Hellman key exchange algorithm). */
#define PHAL_ICODE_TAM_CUSTOMDATA_CLEAR                             0x00U   /**< Macro to represent the custom data value for Tag authentication cleared. */
#define PHAL_ICODE_TAM_CUSTOMDATA_SET                               0x01U   /**< Macro to represent the custom data value for Tag authentication set. */
#define PHAL_ICODE_MAM1_STEP                                        0x00U   /**< Macro to represent the first step value for Mutual authentication. */
#define PHAL_ICODE_MAM2_STEP                                        0x04U   /**< Macro to represent the first second value for Mutual authentication. */

#define PHAL_ICODE_AUTH_PARAM_TAM1_0                                0x00U   /**< Macro to represent Auth Param as TAM1.0. This will be used for WriteCertificate command. */
#define PHAL_ICODE_AUTH_PARAM_TAM1_1                                0x01U   /**< Macro to represent Auth Param as TAM1.1. This will be used for ReadCertificate command. */

/**
 * Updates the Option value to the Flag's information byte. This is the 7th bit (as per ISO15693 notation) of
 * the Flag byte.
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : The option value to update.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF
 *                                  0x01:   PHAL_ICODE_OPTION_ON
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_SetOptionBit(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bUpdateTiming);

/**
 * Sends an EOF information to the VICC based on the status received from the command being exchanged.
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      wExchangeStatus         : The status received from the last command exchange.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteAlikeHandling(void * pPalSli15693DataParams, phStatus_t wExchangeStatus);

/**
 * Computes the custom error code for the ISO15693 specific error codes.
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      wStatus                 : The status of Pal exchange.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ComputeErrorCode(void * pPalSli15693DataParams, phStatus_t wStatus);

/**
 *
 */
phStatus_t phalICode_Int_GetFlags(void * pPalSli15693DataParams, uint16_t * pFlags);

/*
 * Reverses the byte buffer.
 *
 * Input Parameters:
 *      pData                   : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      wLength                 : The length of butes available in pData buffer.
 */
void phalICode_Int_Reverse(uint8_t * pData, uint16_t wLength);

/*
 * Performs the reading data or status of multiple blocks.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bCmdCode                : Command code for the flavours of Multiple Block Read.
 *                                  0x23:   PHAL_ICODE_CMD_READ_MULTIPLE_BLOCKS
 *                                  0x2C:   PHAL_ICODE_CMD_GET_MULTIPLE_BLOCK_SECURITY_STATUS
 *                                  0x2D:   PHAL_ICODE_CMD_FAST_READ_MULTIPLE_BLOCKS
 *                                  0x33:   PHAL_ICODE_CMD_EXTENDED_READ_MULTIPLE_BLOCKS
 *                                  0x3C:   PHAL_ICODE_CMD_EXTENDED_GET_MULTIPLE_BLOCK_SECURITY_STATUS
 *                                  0x3D:   PHAL_ICODE_CMD_EXTENDED_FAST_READ_MULTIPLE_BLOCKS
 *                                  0xB8:   PHAL_ICODE_CMD_GET_MULTIPLE_BLOCK_PROTECTION_STATUS
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bUpdateTiming           : Update FDT Timeout according to bOption value.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available.)
 *      wBlockNo                : Block number from where the data to be read.
 *      wNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadBlocks(void * pPalSli15693DataParams, uint8_t bCmdCode, uint8_t bEnableBuffering, uint8_t bUpdateTiming,
    uint8_t bOption, uint16_t wBlockNo, uint16_t wNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Performs a Single block read command. When receiving the Read Single Block command, the VICC shall read the requested block and send
 * back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo                : Block number from where the data to be read.
 *
 * Output Parameters:
 *      ppData                  : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadSingleBlock(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bBlockNo, uint8_t ** ppData,
        uint16_t * pDataLen);

/*
 * Performs a Single block write command. When receiving the Write single block command, the VICC shall write the requested block with the
 * data contained in the request and report the success of the operation in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON)
 * is set in the request, the VICC shall wait for the reception of an EOF from the VCD and upon such reception shall return its response.
 * If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its response when it has completed the write operation starting
 * after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon
 * detection of the rising edge of the EOF of the VCD request. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      bBlockNo                : Block number to which the data should be written.
 *      pData                   : Information to be written to the specified block number.
 *      bDataLen                : Number of bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteSingleBlock(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bBlockNo, uint8_t * pData,
        uint8_t bDataLen);

/*
 * Performs a Lock block command. When receiving the Lock block command, the VICC shall lock permanently the requested block. If the
 * Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the VCD
 * and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 * (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      bBlockNo                : Block number which should be locked.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockBlock(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bBlockNo);

/*
 * Performs a Multiple block read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s) and send
 * back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall
 * return only the block value. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo                : Block number from where the data to be read.
 *      bNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadMultipleBlocks(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint8_t bBlockNo,
        uint8_t bNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Performs a WriteAFI command. When receiving the Write AFI request, the VICC shall write the  AFI value into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the write operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      bAfi                    : Value of Application Family Identifier.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteAFI(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bAfi);

/*
 * Performs a LockAFI command. When receiving the Lock AFI request, the VICC shall lock the AFI value permanently into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockAFI(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * Performs WriteDSFID command. When receiving the Write DSFID request, the VICC shall write the DSFID value into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF
 * from the VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC
 * shall return its response when it has completed the write operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a
 * multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the
 * EOF of the VCD request. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      bDsfid          : Value of DSFID (data storage format identifier).
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteDSFID(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bDsfid);

/*
 * Performs LockDSFID command. When receiving the Lock DSFID request, the VICC shall lock the DSFID value permanently into its memory.
 * If the  Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the
 * VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us)
 * with a total tolerance of  32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockDSFID(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * Performs GetSystemInformation command. This command allows for retrieving the system information value from the VICC.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      ppSystemInfo            : The system information of the VICC.
 *      pSystemInfoLen          : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetSystemInformation(void * pPalSli15693DataParams, uint8_t ** ppSystemInfo, uint16_t * pSystemInfoLen);

/*
 * Performs GetMultipleBlockSecurityStatus. When receiving the Get multiple block security status command, the VICC
 * shall send back the block security status.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bBlockNo                : Block number for which the status should be returned.
 *      bNoOfBlocks             : Number of blocks to be used for returning the status.
 *
 * Output Parameters:
 *      pStatus                 : The status of the block number mentioned in bBlockNo until bNoOfBlocks.
 *      pStatusLen              : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetMultipleBlockSecurityStatus(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bBlockNo, uint8_t bNoOfBlocks,
        uint8_t * pStatus, uint16_t * pStatusLen);

/*
 * Performs a Multiple block fast read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s) and
 * send back its value in the response. If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block
 * security status, followed by the block value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall
 * return only the block value. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo                : Block number from where the data to be read.
 *      bNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_FastReadMultipleBlocks(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint8_t bBlockNo, uint8_t bNumBlocks,
        uint8_t * pData, uint16_t * pDataLen);

/**
 * \brief Performs a Extended Single block read command. When receiving the Extended Read Single Block command, the VICC shall read the
 * requested block and send back its value in the response. If a VICC supports Extended read single block command, it shall also support
 * Read single block command for the first 256 blocks of memory. If the Option_flag (bOption = #PHAL_ICODE_OPTION_ON) is set in the request,
 * the VICC shall return the block security status, followed by the block value. If it is not set (bOption = #PHAL_ICODE_OPTION_OFF), the
 * VICC shall return only the block value. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                                available in the first byte of ppData buffer.)
 *      wBlockNo                : Block number from where the data to be read.
 *
 * Output Parameters:
 *      ppData                  : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedReadSingleBlock(void * pPalSli15693DataParams, uint8_t bOption, uint16_t wBlockNo, uint8_t ** ppData,
        uint16_t * pDataLen);

/**
 * \brief Performs a Extended Single block Write command. When receiving the Extended write single block command, the VICC shall write the
 * requested block with the data contained in the request and report the success of the operation in the response. If a VICC supports
 * Extended write single block command, it shall also support Write single block command for the first 256 blocks of memory.
 *
 * If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its response when it has completed the write operation starting
 * after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc (302 us) with a total tolerance of  32/fc and latest after 20 ms upon
 * detection of the rising edge of the EOF of the VCD request. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                        shall return its response.)
 *      wBlockNo                : Block number to which the data should be written.
 *      pData                   : Information to be written to the specified block number.
 *      bDataLen                : Number of bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedWriteSingleBlock(void * pPalSli15693DataParams, uint8_t bOption, uint16_t wBlockNo, uint8_t * pData, uint8_t bDataLen);

/*
 * Performs a Extended Lock block command. When receiving the Lock block command, the VICC shall lock permanently the requested
 * block. If a VICC supports Extended lock block command, it shall also support Lock block command for the first 256 blocks of memory.
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall wait for the reception of an EOF from the
 * VCD and upon such reception shall return its response. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return its
 * response when it has completed the lock operation starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 * (302 us) with a total tolerance of 32/fc and latest after 20 ms upon detection of the rising edge of the EOF of the VCD request.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the lock operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of  32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      wBlockNo                : Block number which should be locked.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedLockBlock(void * pPalSli15693DataParams, uint8_t bOption, uint16_t wBlockNo);

/*
 * Performs a Extended Multiple block read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s)
 * and send back its value in the response. If a VICC supports Extended read multiple blocks command, it shall also support Read multiple blocks
 * command for the first 256 blocks of memory.
 *
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block security status, followed by the block
 * value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      wBlockNo                : Block number from where the data to be read.
 *      wNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedReadMultipleBlocks(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint16_t wBlockNo,
        uint16_t wNumBlocks, uint8_t * pData, uint16_t * pDataLen);

#ifdef NXPBUILD__PH_CRYPTOSYM
/*
 * Performs tag authentication with the card. This is another method of authenticating with the card.
 * Here the TAM1 challenge message is sent to the card. The card does not respond for this command.
 * To verify if this command was success the command phalIcodeDna_ReadBuffer should be called.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      pCryptoRngDataParams    : Pointer to the parameter structure of the underlying Crypto RNG layer.
 *      pRndNo                  : Random number buiffer of Internal parameter structure.
 *      bKeyNoCard              : Block number of the AES key available in the card.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_Challenge(void * pPalSli15693DataParams, void * pCryptoRngDataParams, uint8_t * pRndNo, uint8_t bKeyNoCard);

/*
 * Reads the crypto calculation result of previous Challenge command. If the Challenge Command was success,
 * Then the encrypted response will be returned. The response will be same as TAM1 response format. If verification
 * is enabled (i.e. bVerify = 0x01), The encrypted response will be decrypted and the random number generated by the
 * Challenge command will be compared againt the received one. If fails AUTH_ERROR will be returned.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      wCompID                 : Software of Sam compoent ID of this layer.
 *      pCryptoRngDataParams    : Pointer to the parameter structure of the underlying Crypto RNG layer.
 *      pKeyStoreDataParams     : Pointer to the parameter structure of the underlying KeyStore layer.
 *      pRndNo                  : Random number buiffer of Internal parameter structure.
 *      bVerify                 : To verify the received data with the random number generated by Challenge command.
 *                                  0x00: Disable verification
 *                                  0x01: Enable verification
 *      bKeyNo                  : AES key address in software key store.
 *      bKeyVer                 : AES key version to be used.
 *
 * Output Parameters:
 *      ppResponse              : If verification is enabled the decrypted response data will be available. Also
 *                                the response will be verified with the random number generated by
 *                                \ref phalICode_Challenge command.
 *                                If verification is disabled the encrypted response data will be available.
 *      pRespLen                : Length of available bytes in ppResponse buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadBuffer(uint16_t wCompID, void * pPalSli15693DataParams, void * pCryptoDataParams, void * pKeyStoreDataParams, uint8_t * pRndNo,
        uint8_t bVerify, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t ** ppResponse, uint16_t * pRespLen);
#endif /* NXPBUILD__PH_CRYPTOSYM */
/*
 * Performs ExtendedGetSystemInformation command. This command allows for retrieving the system information value
 * from the VICC and shall be supported by the VICC if extended memory or security functionalities are supported
 * by the VICC. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bInfoParams             : Extend Get System Information parameter request fields.
 *                                  0x10: PHAL_ICODE_INFO_PARAMS_REQUEST_DEFAULT
 *                                  0x01: PHAL_ICODE_INFO_PARAMS_REQUEST_DSFID
 *                                  0x02: PHAL_ICODE_INFO_PARAMS_REQUEST_AFI
 *                                  0x04: PHAL_ICODE_INFO_PARAMS_REQUEST_VICC_MEM_SIZE
 *                                  0x08: PHAL_ICODE_INFO_PARAMS_REQUEST_IC_REFERENCE
 *                                  0x10: PHAL_ICODE_INFO_PARAMS_REQUEST_MOI
 *                                  0x20: PHAL_ICODE_INFO_PARAMS_REQUEST_COMMAND_LIST
 *                                  0x50: PHAL_ICODE_INFO_PARAMS_REQUEST_CSI_INFORMATION
 *                                  0x80: PHAL_ICODE_INFO_PARAMS_REQUEST_EXT_GET_SYS_INFO
 *
 * Output Parameters:
 *      ppSystemInfo            : The system information of the VICC.
 *      pSystemInfoLen          : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedGetSystemInformation(void * pPalSli15693DataParams, uint8_t bInfoParams, uint8_t ** ppSystemInfo,
        uint16_t * pSystemInfoLen);

/*
 * Performs ExtendedGetMultipleBlockSecurityStatus. When receiving the Extended Get multiple block security status
 * command, the VICC shall send back the block security status. The blocks are numbered from 0000 to FFFF (0 - 65535).
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      wBlockNo                : Block number for which the status should be returned.
 *      wNoOfBlocks             : Number of blocks to be used for returning the status.
 *
 * Output Parameters:
 *      pStatus                 : The status of the block number mentioned in wBlockNo until wNoOfBlocks.
 *      pStatusLen              : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedGetMultipleBlockSecurityStatus(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint16_t wBlockNo, uint16_t wNoOfBlocks,
        uint8_t * pStatus, uint16_t * pStatusLen);

/*
 * Performs a Extended Multiple block fast read command. When receiving the Read Multiple Block command, the VICC shall read the requested block(s)
 * and send back its value in the response. If a VICC supports Extended read multiple blocks command, it shall also support Read multiple blocks
 * command for the first 256 blocks of memory.
 *
 * If the Option_flag (bOption = PHAL_ICODE_OPTION_ON) is set in the request, the VICC shall return the block security status, followed by the block
 * value sequentially block by block. If it is not set (bOption = PHAL_ICODE_OPTION_OFF), the VICC shall return only the block value.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      wBlockNo                : Block number from where the data to be read.
 *      wNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ExtendedFastReadMultipleBlocks(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint16_t wBlockNo,
        uint16_t wNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * This command enables the EAS mode if the EAS mode is not locked. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword. This interface will be common
 * for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Options to be enabled or disabled. As per ISO15693 protocol
 *                                  0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                                  0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_SetEAS(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * This command disables the EAS mode if the EAS mode is not locked. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword. This interface will be common
 * for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Options to be enabled or disabled. As per ISO15693 protocol
 *                                  0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                                  0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ResetEAS(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * This command locks the current state of the EAS mode and the EAS ID. If the EAS mode is password protected
 * the EAS password has to be transmitted before with \ref phalICode_SetPassword. This interface will be common
 * for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Options to be enabled or disabled. As per ISO15693 protocol
 *                                  0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                                  0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockEAS(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * This command returns the EAS sequence if the EAS mode is enabled. This interface will be common
 * for Software and Sam_NonX layers.
 *
 * bOption disabled: bEasIdMaskLength and pEasIdValue are not transmitted, EAS Sequence is returned;
 * bOption enabled and bEasIdMaskLength = 0: EAS ID is returned;
 * bOption enabled and bEasIdMaskLength > 0: EAS Sequence is returned by ICs with matching pEasIdValue;
 *
 * If the EAS mode is disabled, the label remains silent.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Option flag;
 *                                  PHAL_ICODE_OPTION_OFF
 *                                      EAS ID mask length and EAS ID value shall not be transmitted.
 *                                      If the EAS mode is enabled, the EAS response is returned from the ICODE IC.
 *                                      This configuration is compliant with the EAS command of the ICODE IC
 *                                  PHAL_ICODE_OPTION_ON.
 *                                      Within the command the EAS ID mask length has to be transmitted to identify how
 *                                      many bits of the following EAS ID value are valid (multiple of 8-bits). Only those
 *                                      ICODE ICs will respond with the EAS sequence which have stored the corresponding
 *                                      data in the EAS ID configuration (selective EAS) and if the EAS Mode is set.
 *                                      If the EAS ID mask length is set to 0, the ICODE IC will answer with its EAS ID
 *      pEasIdValue             : EAS ID; 0, 8 or 16 bits; optional.
 *      bEasIdMaskLen           : 8 bits; optional.
 *
 * Input Parameters:
 *      ppEas                   : EAS ID (16 bits) or EAS Sequence (256 bits).
 *      pEasLen                 : Length of bytes available in ppEas buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_EASAlarm(void * pPalSli15693DataParams, uint8_t bOption, uint8_t * pEasIdValue, uint8_t bEasIdMaskLen, uint8_t ** ppEas,
        uint16_t * pEasLen);

/*
 * This command enables the password protection for EAS. The EAS password has to be transmitted before with
 * \ref phalICode_SetPassword.. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_PasswordProtectEAS(void * pPalSli15693DataParams);

/*
 * This command enables the password protection for AFI. The AFI password has to be transmitted before with
 * \ref phalICode_SetPassword.. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_PasswordProtectAFI(void * pPalSli15693DataParams);

/*
 * With this command, a new EAS identifier is stored in the corresponding configuration memory. If the EAS mode
 * is password protected the EAS password has to be transmitted before with \ref phalICode_SetPassword. This interface
 * will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pEasIdValue             : EAS ID; 16 bits.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteEAS_ID(void * pPalSli15693DataParams, uint8_t bOption, uint8_t * pEasIdValue);

/*
 * On this command, the label will respond with it's EPC data. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      ppEpc                   : EPC data; 96 bits.
 *      pEpcLen                 : Length of bytes available in ppEpc buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadEPC(void * pPalSli15693DataParams, uint8_t ** ppEpc, uint16_t * pEpcLen);

/*
 * Performs GetNXPSystemInformation command. This command allows for retrieving the NXP system information value from the VICC.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      ppSystemInfo            : The NXP system information of the VICC.
 *      pSystemInfoLen          : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetNXPSystemInformation(void * pPalSli15693DataParams, uint8_t ** ppSystemInfo, uint16_t * pSystemInfoLen);

/*
 * Performs a GetRandomNumber command. On this command, the label will respond with a random number.
 * The received random number shall be used to diversify the password for the \ref phalICode_SetPassword command.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      ppRnd                   : Random number; 16 bits.
 *      ppRnd                   : Number of bytes in ppRnd buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetRandomNumber(void * pPalSli15693DataParams, uint8_t ** ppRnd, uint16_t * pRndLen);

/*
 * Perforns SetPassword command. With this command the different passwords can be transmitted to the label.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * This command has to be executed just once for the related passwords if the label is powered.
 *
 * \verbatim
 * [XOR password calculation example]
 * pXorPwd[0] = pPassword[0] ^ pRnd[0];
 * pXorPwd[1] = pPassword[1] ^ pRnd[1];
 * pXorPwd[2] = pPassword[2] ^ pRnd[0];
 * pXorPwd[3] = pPassword[3] ^ pRnd[1];
 * \endverbatim
 *
 * \b Remark: This command can only be executed in addressed or selected mode except of Privay Password.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier          : Password Identifier.
 *                                  PHAL_ICODE_SET_PASSWORD_READ
 *                                  PHAL_ICODE_SET_PASSWORD_WRITE
 *                                  PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                                  PHAL_ICODE_SET_PASSWORD_DESTROY
 *                                  PHAL_ICODE_SET_PASSWORD_EAS
 *      pXorPwd                 : XOR Password; 32 bits.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_SetPassword(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bPwdIdentifier, uint8_t * pXorPwd);

/*
 * Performs WritePassword command. With this command, a new password is written into the related memory. Note that the
 * old password has to be transmitted before with \ref phalICode_SetPassword. The new password takes effect immediately which
 * means that the new password has to be transmitted with \ref phalICode_SetPassword to get access to protected blocks/pages.
 * \b Remark: This command can only be executed in addressed or selected mode.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier          : Password Identifier.
 *                                  PHAL_ICODE_SET_PASSWORD_READ
 *                                  PHAL_ICODE_SET_PASSWORD_WRITE
 *                                  PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                                  PHAL_ICODE_SET_PASSWORD_DESTROY
 *                                  PHAL_ICODE_SET_PASSWORD_EAS
 *      pPwd                    : Plain Password; 32 bits
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WritePassword(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bPwdIdentifier, uint8_t * pPwd);

/*
 * Performs LockPassword command. This command locks the addressed password. Note that the addressed password
 * has to be transmitted before with \ref phalICode_SetPassword. A locked password can not be changed any longer.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPwdIdentifier          : Password Identifier.
 *                                  PHAL_ICODE_SET_PASSWORD_READ
 *                                  PHAL_ICODE_SET_PASSWORD_WRITE
 *                                  PHAL_ICODE_SET_PASSWORD_PRIVACY
 *                                  PHAL_ICODE_SET_PASSWORD_DESTROY
 *                                  PHAL_ICODE_SET_PASSWORD_EAS
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockPassword(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bPwdIdentifier);

/*
 * Performs Page protection command. This command changes the protection status of a page. Note that the related
 * passwords have to be transmitted before with \ref phalICode_SetPassword if the page is not public.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPPAdd_PageNo           : Page number to be protected in case of products that do not have pages
 *                                charactersized as high and Low.
 *                                Block number to be protected in case of products that have pages
 *                                charactersized as high and Low.
 *      bProtectionStatus       : Protection status options for the products that do not have pages
 *                                charactersized as high and Low.
 *                                  0x00: PHAL_ICODE_PROTECT_PAGE_PUBLIC
 *                                  0x01: PHAL_ICODE_PROTECT_PAGE_READ_WRITE_READ_PASSWORD
 *                                  0x10: PHAL_ICODE_PROTECT_PAGE_WRITE_PASSWORD
 *                                  0x11: PHAL_ICODE_PROTECT_PAGE_READ_WRITE_PASSWORD_SEPERATE
 *
 *                                Extended Protection status options for the products that have pages
 *                                charactersized as high and Low.
 *                                  0x01: PHAL_ICODE_PROTECT_PAGE_READ_LOW
 *                                  0x02: PHAL_ICODE_PROTECT_PAGE_WRITE_LOW
 *                                  0x10: PHAL_ICODE_PROTECT_PAGE_READ_HIGH
 *                                  0x20: PHAL_ICODE_PROTECT_PAGE_WRITE_HIGH
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ProtectPage(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bPPAdd_PageNo, uint8_t bProtectionStatus);

/*
 * Perform LockPageProtectionCondition command. This command permanenty locks the protection status of a page.
 * Note that the related passwords have to be transmitted before with \ref phalICode_SetPassword if the page is
 * not public. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bPageNo                 : Page number to be protected.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_LockPageProtectionCondition(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bPageNo);

/*
 * Perform GetMultipleBlockProtectionStatus command. This instructs the label to return the block protection
 * status of the requested blocks. This interface will be common for Software and Sam_NonX layers.
 *
 * Remark: If bBlockNo + bNoOfBlocks exceeds the total available number of user blocks, the number of received
 * status bytes is less than the requested number. This means that the last returned status byte corresponds to the
 * highest available user block.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bBlockNo                : First Block number.
 *      bNoOfBlocks             : Number of blocks.
 *
 * Output Parameters:
 *      pProtectionStates       : Protection states of requested blocks.
 *      pNumReceivedStates      : Number of received block protection states.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetMultipleBlockProtectionStatus(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bBlockNo, uint8_t bNoOfBlocks,
        uint8_t * pProtectionStates, uint16_t * pNumReceivedStates);

/*
 * Performs Destroy command. This command permanently destroys the label. This interface will be common for Software and Sam_NonX layers.
 *
 * The Destroy password has to be transmitted before with \ref phalICode_SetPassword.
 * Remark: This command is irreversible and the label will never respond to any command again.
 * Remark: This command can only be executed in addressed or selected mode.
 *
 * Note: This command is not valid for ICode Dna product as the Destroy feature is part of Mutual
 * Authentication command (refer \ref phalICode_AuthenticateMAM).
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pXorPwd                 : XOR Password; 32 bits. Pass the password for the ICODE products that supports (eg: SLIX-L) and NULL
 *                                for the products that do not support.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_Destroy(void * pPalSli15693DataParams, uint8_t bOption, uint8_t * pXorPwd);

/*
 * Performs EnablePrivacy command. This command instructs the label to enter privacy mode. This interface will be common
 * for Software and Sam_NonX layers.
 *
 * In privacy mode, the label will only respond to \ref phalSli_GetRandomNumber and \ref phalICode_SetPassword commands.
 * To get out of the privacy mode, the Privacy password has to be transmitted before with \ref phalICode_SetPassword.
 *
 * Note: This command is not valid for ICode Dna product as the Destroy feature is part of Mutual
 * Authentication command (refer \ref phalICode_AuthenticateMAM).
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      pXorPwd                 : XOR Password; 32 bits. Pass the password for the ICODE products that supports and NULL
 *                                for the products that do not support.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_EnablePrivacy(void * pPalSli15693DataParams, uint8_t bOption, uint8_t * pXorPwd);

/*
 * Perform 64-BitPasswordProtection command. This instructs the label that both of the Read and Write passwords
 * are required for protected access. This interface will be common for Software and Sam_NonX layers.
 *
 * Note that both the Read and Write passwords have to be transmitted before with \ref phalICode_SetPassword.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_64BitPasswordProtection(void * pPalSli15693DataParams, uint8_t bOption);

/*
 * Performs ReadSignature command. On this command, the label will respond with the signature value.
 * This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      ppSign                  : The originality signature returned by the VICC.
 *      ppSign                  : Length of originality signature buffer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadSignature(void * pPalSli15693DataParams, uint8_t ** ppSign, uint16_t * pSignLen);

/*
 * Reads a multiple 4 byte(s) data from the mentioned configuration block address. Here the starting address of the
 * configuration block should be given in the parameter bBlockAddr and the number of blocks to read from the starting
 * block should be given in the parameter bNoOfBlocks. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption             : Options to be enabled or disabled. As per ISO15693 protocol
 *                              0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                              0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bBlockAddr              : Configuration block address.
 *      bNoOfBlocks             : The n block(s) to read the configuration data.
 *
 * Output Parameters:
 *      ppData                  : Multiple of 4 (4u * No Of Blocks) byte(s) of data read from the mentioned
 *                                configuration block address.
 *      pDataLen                : Number of received configuration data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadConfig(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bBlockAddr, uint8_t bNoOfBlocks,
    uint8_t ** ppData, uint16_t * pDataLen);

/*
 * Writes a 4 byte data to the mentioned configuration block address. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bOption                 : Options to be enabled or disabled. As per ISO15693 protocol
 *                                  0x00:   PHAL_ICODE_OPTION_OFF Disable option.
 *                                  0x01:   PHAL_ICODE_OPTION_ON Enable option.
 *      bBlockAddr              : Configuration block address.
 *      pData                   : A 4 byte data to be written to the mentioned configuration block address.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteConfig(void * pPalSli15693DataParams, uint8_t bOption, uint8_t bBlockAddr, uint8_t * pData);

/*
 * Enables the random ID generation in the tag. This interfaces is used to instruct the tag to generate
 * a random number in privacy mode. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_PickRandomID(void * pPalSli15693DataParams);

/**
 * \brief Provides the tag tamper status.
 *
 * Flag can be set using \ref phalICode_SetConfig "SetConfig" utility interface
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If any of the DataParams are null.
 * \retval #PH_ERR_INVALID_PARAMETER
 *          - If the buffers are null.
 *          - For the option values that are not supported.
 * \retval XXXX
 *                                      - Depending on status codes return by PICC.
 *                                      - Other Depending on implementation and underlying component.
 */
phStatus_t phalICode_Int_ReadTT(void * pPalSli15693DataParams, uint8_t bOption, uint8_t ** ppResponse, uint16_t * pRspLen);

/*
 * Performs Parameter Request command. When receiving VICC PARAMETER REQUEST, NTAG5 I2C returns all supported bit rates
 * and timing information. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to this layer's parameter structure.
 *
 * Output Parameters:
 *      pBitRate                : One byte buffer containing the supported bitrates.
 *                                  0x00: PHAL_ICODE_PARAMETERS_BITRATE_26KBPS_BOTH_DIRECTIONS
 *                                  0x01: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VCD_VICC
 *                                  0x02: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VCD_VICC
 *                                  0x04: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VCD_VICC
 *                                  0x10: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VICC_VCD
 *                                  0x20: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VICC_VCD
 *                                  0x40: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VICC_VCD
 *      pTiming                 : One byte buffer containing the supported bitrates.
 *                                  0x00: PHAL_ICODE_PARAMETERS_TIMING_320_9_US
 *                                  0x01: PHAL_ICODE_PARAMETERS_TIMING_160_5_US
 *                                  0x02: PHAL_ICODE_PARAMETERS_TIMING_80_2_US
 *                                  0x04: PHAL_ICODE_PARAMETERS_TIMING_SAME_BOTH_DIRECTIONS
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ParameterRequest(void * pPalSli15693DataParams, uint8_t * pBitRate, uint8_t * pTiming);

/*
 * Performs Parameter Select command. PARAMETER SELECT command is used to activate one bit rate combination and the T1
 * timing indicated in PARAMETER REQUEST response. Only one option in each direction shall be chosen. After the response
 * to PARAMETER SELECT command, new parameters are valid. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to this layer's parameter structure.
 *      pBitRate                : One byte buffer containing the supported bitrates.
 *                                  0x00: PHAL_ICODE_PARAMETERS_BITRATE_26KBPS_BOTH_DIRECTIONS
 *                                  0x01: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VCD_VICC
 *                                  0x02: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VCD_VICC
 *                                  0x04: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VCD_VICC
 *                                  0x10: PHAL_ICODE_PARAMETERS_BITRATE_53KBPS_VICC_VCD
 *                                  0x20: PHAL_ICODE_PARAMETERS_BITRATE_106KBPS_VICC_VCD
 *                                  0x40: PHAL_ICODE_PARAMETERS_BITRATE_212KBPS_VICC_VCD
 *      pTiming                 : One byte buffer containing the supported bitrates.
 *                                  0x00: PHAL_ICODE_PARAMETERS_TIMING_320_9_US
 *                                  0x01: PHAL_ICODE_PARAMETERS_TIMING_160_5_US
 *                                  0x02: PHAL_ICODE_PARAMETERS_TIMING_80_2_US
 *                                  0x04: PHAL_ICODE_PARAMETERS_TIMING_SAME_BOTH_DIRECTIONS
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ParameterSelect(void * pPalSli15693DataParams, uint8_t bBitRate, uint8_t bTiming);

/*
 * Performs a SRAM Read command. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (Block Security Status information is not available. Only block data is available.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (Both Block Security Status information and Block Data is available. This will be
 *                                                        available in the first byte of ppData buffer.)
 *      bBlockNo                : Block number from where the data to be read.
 *      bNumBlocks              : Total number of block to read.
 *
 * Output Parameters:
 *      pData                   : Information received from VICC in with respect to bOption parameter information.
 *      pDataLen                : Number of received data bytes.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_ReadSRAM(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint8_t bBlockNo,
    uint8_t bNumBlocks, uint8_t * pData, uint16_t * pDataLen);

/*
 * Performs a SRAM Write command. This interface will be common for Software and Sam_NonX layers.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bEnableBuffering        : Option for bufferring the response data.
 *                                  0x00:   PHAL_ICODE_DISABLE (Option to disable the buffering of response data)
 *                                  0x01:   PHAL_ICODE_ENABLE (Option to enable the buffering of response data)
 *      bOption                 : Option flag.
 *                                  0x00:   PHAL_ICODE_OPTION_OFF (The VICC shall return its response when it has completed the write operation
 *                                                                 starting after t1nom [4352/fc (320,9 us), see 9.1.1] + a multiple of 4096/fc
 *                                                                 (302 us) with a total tolerance of 32/fc and latest after 20 ms upon detection
 *                                                                 of the rising edge of the EOF of the VCD request.)
 *                                  0x01:   PHAL_ICODE_OPTION_ON (The VICC shall wait for the reception of an EOF from the VCD and upon such reception
 *                                                                shall return its response.)
 *      bBlockNo                : Block number from where the data should be written.
 *      bNumBlocks              : Total number of block to be written.
 *      pData                   : Information to be written to VICC.
 *      wDataLen                : Number of data bytes to be written.
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_WriteSRAM(void * pPalSli15693DataParams, uint8_t bEnableBuffering, uint8_t bOption, uint8_t bBlockNo, uint8_t bNumBlocks,
    uint8_t * pData, uint16_t wDataLen);

/*
 * Performs a I2CM Read command. This command is used to read from any I2C slave connected to NTAG5 I2C Host.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bAddr_Config            : I2C Slave address from which the data should be read and the information
 *                                to set the Stop bit.
 *                                  Bits 0 - 6: Is for slave address. Its 7 bit address.
 *                                  Bit 7     : Configuration Bit
 *                                              0b: Generate stop condition
 *                                              1b: Don't generate stop condition
 *      bDataLen                : Total Number of data bytes to be read. If 1 byte has to be read then the
 *                                length will be 1.
 *
 * Output Parameters:
 *      pData                   : Information to be read from the VICC.

 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_I2CMRead (void * pPalSli15693DataParams, uint8_t bI2CParam, uint16_t wDataLen, uint8_t * pData);

/*
 * Performs a I2CM Write command. This command is used to write to any I2C slave connected to NTAG5 I2C Host.
 *
 * Flag can be set by using \ref phalICode_SetConfig command
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *      bAddr_Config            : I2C Slave address to which the data should be written and the information
 *                                to set the Stop bit.
 *                                  Bits 0 - 6: Is for slave address. Its 7 bit address.
 *                                  Bit 7     : Configuration Bit
 *                                              0b: Generate stop condition
 *                                              1b: Don't generate stop condition
 *      pData                   : Information to be written to the VICC.
 *      bDataLen                : Total Number of data bytes to be written. If 1 byte has to be written then the
 *                                length will be 1.

 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_I2CMWrite (void * pPalSli15693DataParams, uint8_t bI2CParam, uint8_t * pData, uint16_t wDataLen);

/*
 * Get the type of Tag
 *
 * Input Parameters:
 *      pPalSli15693DataParams  : Pointer to the parameter structure of the underlying palSli15693 layer.
 *
 * Output Parameters:
 *      pTagType                : The type of ICode tag.
 *                                  0xFFFF: PHAL_ICODE_TAG_TYPE_UNKNOWN
 *                                  0x0001: PHAL_ICODE_TAG_TYPE_ICODE_SLI
 *                                  0x0002: PHAL_ICODE_TAG_TYPE_ICODE_SLI_S
 *                                  0x0003: PHAL_ICODE_TAG_TYPE_ICODE_SLI_L
 *                                  0x5001: PHAL_ICODE_TAG_TYPE_ICODE_SLIX
 *                                  0x5002: PHAL_ICODE_TAG_TYPE_ICODE_SLIX_S
 *                                  0x5003: PHAL_ICODE_TAG_TYPE_ICODE_SLIX_L
 *                                  0x0801: PHAL_ICODE_TAG_TYPE_ICODE_SLI_X2
 *                                  0x1801: PHAL_ICODE_TAG_TYPE_ICODE_DNA
 *                                  0x5801: PHAL_ICODE_TAG_TYPE_ICODE_NTAG5_I2C
 *
 * Return:
 *          PH_ERR_SUCCESS for successfull operation.
 *          Other Depending on implementation and underlaying component.
 */
phStatus_t phalICode_Int_GetTagType(void * pPalSli15693DataParams, uint16_t * pTagType);
#endif /* PHALICODE_INT_H */
