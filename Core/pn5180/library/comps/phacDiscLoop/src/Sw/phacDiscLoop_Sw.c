/*----------------------------------------------------------------------------*/
/* Copyright 2016-2024 NXP                                                    */
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
* This File contains all functions that's needed by Discovery Loop
* for Starting the discovery loop, Set & Get Configuration and Card Activation,
* as part of the Reader Library Framework.
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*
*/
#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <phacDiscLoop.h>
#include <phhalHw.h>

#include <phpalI14443p3a.h>
#include <phpalI14443p3b.h>
#include <phpalI14443p4a.h>
#include <phpalI14443p4.h>
#include <phpalFelica.h>
#include <phpalI18000p3m3.h>
#include <phpalSli15693.h>
#include <phpalI18092mPI.h>

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
#include "phacDiscLoop_Sw.h"
#include "phacDiscLoop_Sw_Int.h"

/*********************************************************************************/
/** LOCALIZED GLOBAL VARIABLES                                                   */
/*********************************************************************************/
static const uint8_t gPasTechPollSeqMapTable[] = {
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_A,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_B,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F212,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_F424,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_V,
    (uint8_t)PHAC_DISCLOOP_TECH_TYPE_18000P3M3,
};

phStatus_t phacDiscLoop_Sw_Init(
                                phacDiscLoop_Sw_DataParams_t * pDataParams,
                                uint16_t wSizeOfDataParams,
                                void * pHalDataParams
                                )
{
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    uint8_t PH_MEMLOC_COUNT bCardIndex;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS */

    if (sizeof(phacDiscLoop_Sw_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AC_DISCLOOP);
    }

    PH_ASSERT_NULL(pDataParams);

    /* Initialize the private data */
    pDataParams->wId                      = PH_COMP_AC_DISCLOOP | PHAC_DISCLOOP_SW_ID;
    pDataParams->pHalDataParams           = pHalDataParams;
    pDataParams->pPal1443p3aDataParams    = NULL;
    pDataParams->pPal1443p3bDataParams    = NULL;
    pDataParams->pPal14443p4DataParams    = NULL;
    pDataParams->pPalFelicaDataParams     = NULL;
    pDataParams->pPal1443p4aDataParams    = NULL;
    pDataParams->pPalSli15693DataParams   = NULL;
    pDataParams->pPal18000p3m3DataParams  = NULL;
    pDataParams->pAl18000p3m3DataParams   = NULL;
    pDataParams->pPal18092mPIDataParams   = NULL;
    pDataParams->pAlT1TDataParams         = NULL;

    /* Default Operation Mode is NFC */
    pDataParams->bOpeMode                 = RD_LIB_MODE_NFC;
    pDataParams->bNfcActivityVersion      = PHAC_DISCLOOP_NFC_ACTIVITY_VERSION_2_2;

    /* Default listen and poll mode technologies */
    pDataParams->bPollState               = PHAC_DISCLOOP_POLL_STATE_DETECTION;
    pDataParams->bPasPollTechCfg          = 0x00;
    pDataParams->bPasLisTechCfg           = 0x00;
    pDataParams->bActPollTechCfg          = 0x00;
    pDataParams->bActLisTechCfg           = 0x00;

    pDataParams->pPasTechPollSeq          = (uint8_t *)&gPasTechPollSeqMapTable;

    pDataParams->bUseAntiColl             = PH_ON;
    pDataParams->bLpcdEnabled             = PH_OFF;

    pDataParams->bNumOfCards              = 0x00;
    pDataParams->bDetectedTechs           = 0x00;
    pDataParams->bCollPend                = 0x00;
    pDataParams->wActPollGTimeUs          = PH_NXPNFCRDLIB_CONFIG_TYPEA_GT;

    pDataParams->bPasPollBailOut          = 0x00;

    pDataParams->bFsciMax                 = PH_NXPNFCRDLIB_CONFIG_DEFAULT_FSCI_VALUE;
    pDataParams->bEMVCoPropOpRfFieldReset = PH_OFF;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    /* Poll device limits */
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_A]           = PHAC_DISCLOOP_TYPEA_DEFAULT_DEVICE_LIMIT;
    /* Guard times */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_A]         = PH_NXPNFCRDLIB_CONFIG_TYPEA_GT;
    pDataParams->bPasPollTechCfg                                     |= (PHAC_DISCLOOP_POS_BIT_MASK_A);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE
    pDataParams->bActPollTechCfg                                     |= (PHAC_DISCLOOP_ACT_POS_BIT_MASK_106);
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE
    pDataParams->bPasLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE
    pDataParams->bActLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    /* Poll device limits */
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_B]           = PHAC_DISCLOOP_TYPEB_DEFAULT_DEVICE_LIMIT;
    /* Guard times */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_B]         = PH_NXPNFCRDLIB_CONFIG_TYPEB_GT;
    pDataParams->bPasPollTechCfg                                     |= (PHAC_DISCLOOP_POS_BIT_MASK_B);
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    /* Poll device limits */
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_F212]        = PHAC_DISCLOOP_TYPEF_DEFAULT_DEVICE_LIMIT;
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_F424]        = PHAC_DISCLOOP_TYPEF_DEFAULT_DEVICE_LIMIT;
    /* Guard time GTFB */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F212]      = PH_NXPNFCRDLIB_CONFIG_TYPEF_GT;
    /* Guard time GTBF */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F424]      = PH_NXPNFCRDLIB_CONFIG_B_TO_F_GT;
    pDataParams->bPasPollTechCfg                                     |= (PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424);
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE
    pDataParams->bActPollTechCfg                                     |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_212 ;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE
    pDataParams->bActPollTechCfg                                     |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_424 ;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE
    pDataParams->bPasLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE
    pDataParams->bPasLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE
    pDataParams->bActLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE
    pDataParams->bActLisTechCfg                                      |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    /* Poll device limits */
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_V]      = PHAC_DISCLOOP_TYPEV_DEFAULT_DEVICE_LIMIT;
    /* Guard times */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_V]    = PH_NXPNFCRDLIB_CONFIG_TYPEV_GT;
    pDataParams->bPasPollTechCfg                                |= (PHAC_DISCLOOP_POS_BIT_MASK_V);
#endif  /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    /* Poll device limits */
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_18000P3M3]   = PHAC_DISCLOOP_I18000P3M3_DEFAULT_DEVICE_LIMIT;
    /* Guard times */
    pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_18000P3M3] = PH_NXPNFCRDLIB_CONFIG_I18000P3M3_GT;
    pDataParams->bPasPollTechCfg                                     |= (PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3);
#endif  /* NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
    pDataParams->sTypeATargetInfo.bTotalTagsFound   = 0;

    #if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bDid        = 0;
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bLri        = 0;
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bNadEnable  = 0;
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bNad        = 0;
    #endif

    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bFsdi  = PHPAL_I14443P4A_NFC_FRAMESIZE_MAX;
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bCid   = 0x00;
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bNad   = 0x00;
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDri   = 0x00;
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDsi   = 0x00;
    #endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    pDataParams->sTypeBTargetInfo.bTotalTagsFound   = 0x00;
    pDataParams->sTypeBTargetInfo.bAfiReq           = 0x00;
    pDataParams->sTypeBTargetInfo.bFsdi             = 0x08;
    pDataParams->sTypeBTargetInfo.bCid              = 0x00;
    pDataParams->sTypeBTargetInfo.bNad              = 0x00;
    pDataParams->sTypeBTargetInfo.bDri              = 0x00;
    pDataParams->sTypeBTargetInfo.bDsi              = 0x00;
    pDataParams->sTypeBTargetInfo.bExtendedAtqBbit  = 0x00;

#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    pDataParams->sTypeFTargetInfo.bTotalTagsFound  = 0x00;
    pDataParams->sTypeFTargetInfo.aSystemCode[0]   = 0xFF;
    pDataParams->sTypeFTargetInfo.aSystemCode[1]   = 0xFF;
    pDataParams->sTypeFTargetInfo.bTimeSlot        = PHPAL_FELICA_NUMSLOTS_4;

    for(bCardIndex = 0; bCardIndex < PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED; bCardIndex++)
    {
        /* Clear SLEEP_AF State */
        pDataParams->sTypeFTargetInfo.aTypeFTag[bCardIndex].bSleepAFState = 0U;
    }
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS)  || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)
    pDataParams->sTypeFTargetInfo.sTypeF_P2P.bDid          = 0;
    pDataParams->sTypeFTargetInfo.sTypeF_P2P.bLri          = 0;
    pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNadEnable    = 0;
    pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNad          = 0;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    pDataParams->sTypeVTargetInfo.bTotalTagsFound  = 0x00;
    pDataParams->sTypeVTargetInfo.bFlag            = PHPAL_SLI15693_FLAG_DATA_RATE;
    pDataParams->sTypeVTargetInfo.bMode            = PHPAL_SLI15693_FLAG_ADDRESSED;

#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    pDataParams->sI18000p3m3TargetInfo.bTotalTagsFound  = 0;
    pDataParams->sI18000p3m3TargetInfo.bM               = PHPAL_I18000P3M3_M_MANCHESTER_4;
    pDataParams->sI18000p3m3TargetInfo.bDr              = PHPAL_I18000P3M3_LF_847KHZ;

#endif /* NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TARGET
    pDataParams->sTargetParams.bRetryCount = 0;
#endif /* NXPBUILD__PHAC_DISCLOOP_TARGET */

    return PH_ERR_SUCCESS;
}

// discoveryLoop的核心调度函数：根据入口点参数执行轮询（Poll）模式或监听（Listen）模式的标签发现流程
phStatus_t phacDiscLoop_Sw_Run(
                               phacDiscLoop_Sw_DataParams_t * pDataParams,
                               uint8_t bEntryPoint
                               )
{
    phStatus_t PH_MEMLOC_REM wDiscloopStatus;

    /* 关闭干扰检测 Disable Emd Check */
    PH_CHECK_SUCCESS_FCT(wDiscloopStatus, phhalHw_SetConfig(pDataParams->pHalDataParams, PHHAL_HW_CONFIG_SET_EMD, PH_OFF));

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_JEWEL_TAGS
    PH_CHECK_SUCCESS_FCT(wDiscloopStatus, phhalHw_SetConfig(pDataParams->pHalDataParams, PHHAL_HW_CONFIG_JEWEL_MODE, PH_OFF));
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_JEWEL_TAGS */

    switch (bEntryPoint)
    {
    /* 1.轮询入口 */
    case ((uint8_t)PHAC_DISCLOOP_ENTRY_POINT_POLL):

		/* 低功耗卡检测LPCD */
#ifdef NXPBUILD__PHAC_DISCLOOP_LPCD
        /* Perform LPCD if Enabled. */
        if ((0U != (pDataParams->bLpcdEnabled))
            && (pDataParams->bPollState == PHAC_DISCLOOP_POLL_STATE_DETECTION))
        {
            wDiscloopStatus = phhalHw_Lpcd(pDataParams->pHalDataParams);
            if ((wDiscloopStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
            {
                if ((wDiscloopStatus & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT)
                {
                    return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_NO_TECH_DETECTED, PH_COMP_AC_DISCLOOP); /* No card presence. */
                }

                return wDiscloopStatus; /* Other error. */
            }
        }
#endif /* NXPBUILD__PHAC_DISCLOOP_LPCD */

        /* 1.1 主动轮询模式 Check for active poll configuration */
    	// 如果当前设置了 Active Polling 模式，并且处于“轮询检测”的状态
        if((0U != (pDataParams->bActPollTechCfg))
           && (pDataParams->bPollState == PHAC_DISCLOOP_POLL_STATE_DETECTION))
        {
        	/* 尝试使用不同速率（106/212/424 kbps）的NFC P2P主动通信模式与周围的目标设备建立连接
            *  先关闭 RF 场地 -> 等待恢复时间 -> 设置协议速率 -> 开场 -> 发送 ATR 请求
			*	-> 根据返回状态判断是否成功建立连接
            */
            wDiscloopStatus = phacDiscLoop_Sw_Int_ActivePollMode(pDataParams);
            /* Continue with passive polling, if no peer detected */
            if((wDiscloopStatus & PH_ERR_MASK) != PHAC_DISCLOOP_NO_TECH_DETECTED)
            {
            	// 失败
                if(((wDiscloopStatus & PH_ERR_MASK) != PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED) &&
                    ((wDiscloopStatus & PH_ERR_MASK) != PHAC_DISCLOOP_EXTERNAL_RFON))
                {
                    pDataParams->wErrorCode = wDiscloopStatus;
                    return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_FAILURE, PH_COMP_AC_DISCLOOP);
                }
                // 成功
                return wDiscloopStatus;
            }
            /* Field OFF after Active polling and wait for recovery time. */
            PH_CHECK_SUCCESS_FCT(wDiscloopStatus, phhalHw_FieldOff(pDataParams->pHalDataParams));
            PH_CHECK_SUCCESS_FCT(wDiscloopStatus, phhalHw_Wait(pDataParams->pHalDataParams, PHHAL_HW_TIME_MICROSECONDS, pDataParams->wActPollGTimeUs));
        }

        /* 1.2 被动轮询模式 Check for passive poll configuration */
        if(0U != (pDataParams->bPasPollTechCfg))
        {
            /* Perform the Poll operation and store the Status code. */
            wDiscloopStatus = phacDiscLoop_Sw_Int_PollMode(pDataParams);

            /* If error is from below layer, store it and return failure */
            if((wDiscloopStatus & PH_COMP_MASK) != PH_COMP_AC_DISCLOOP)
            {
                pDataParams->wErrorCode = wDiscloopStatus;
                return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_FAILURE, PH_COMP_AC_DISCLOOP);
            }
            return wDiscloopStatus;
        }
        else
        {
            pDataParams->bDetectedTechs = 0x00;
            pDataParams->bNumOfCards = 0x00;
            return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_NO_TECH_DETECTED, PH_COMP_AC_DISCLOOP);
        }

    /* 2. 监听模式 */
    case ((uint8_t)PHAC_DISCLOOP_ENTRY_POINT_LISTEN):
        /* Check for listen configurations */
        if ((0U != (pDataParams->bPasLisTechCfg)) || (0U != (pDataParams->bActLisTechCfg)))
        {
            /* Turn OFF RF field if already on. */
            PH_CHECK_SUCCESS_FCT(wDiscloopStatus, phhalHw_FieldOff(pDataParams->pHalDataParams));

            /* Perform listen operation and store the Status code. */
            wDiscloopStatus = phacDiscLoop_Sw_Int_ListenMode(pDataParams);

            /* If error is from below layer, store it and return failure */
            if((wDiscloopStatus & PH_COMP_MASK) != PH_COMP_AC_DISCLOOP)
            {
                pDataParams->wErrorCode = wDiscloopStatus;
                return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_FAILURE, PH_COMP_AC_DISCLOOP);
            }
            return wDiscloopStatus;
        }
        else
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

    default:
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
    }
}

phStatus_t phacDiscLoop_Sw_SetConfig(
                                     phacDiscLoop_Sw_DataParams_t * pDataParams,
                                     uint16_t wConfig,
                                     uint16_t wValue
                                     )
{
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;
#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS)
    uint8_t     PH_MEMLOC_REM bIndex;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    uint16_t    PH_MEMLOC_REM wSliConfigFlags = 0U;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS */

    switch(wConfig)
    {
    case PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG:
        pDataParams->bActLisTechCfg = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG:
        pDataParams->bActPollTechCfg = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG:
        pDataParams->bPasLisTechCfg = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_COLLISION_PENDING:
        pDataParams->bCollPend = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE:
        if(!(((wValue & 0x00FFU) == PHAC_DISCLOOP_POLL_STATE_DETECTION) ||
            ((wValue & 0x00FFU) == PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION) ||
            ((wValue & 0x00FFU) == PHAC_DISCLOOP_POLL_STATE_REMOVAL)))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->bPollState = (wValue & 0x00FFU);
        break;

    case PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG:
        pDataParams->bPasPollTechCfg = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_ANTI_COLL:
        pDataParams->bUseAntiColl = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GTA_VALUE_US:
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_A] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GTB_VALUE_US:
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_B] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GTFB_VALUE_US:
        if(wValue < PH_NXPNFCRDLIB_CONFIG_TYPEF_GT)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F212] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GTBF_VALUE_US:
        if(wValue < PH_NXPNFCRDLIB_CONFIG_B_TO_F_GT)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F424] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GTV_VALUE_US:
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_V] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GT18000P3M3_VALUE_US:
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_18000P3M3] = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_EMVCO_PROP_OP_RF_RESET:
        if ((((uint8_t)wValue & PHAC_DISCLOOP_POS_BIT_MASK_A) == PHAC_DISCLOOP_POS_BIT_MASK_A) ||
            (((uint8_t)wValue & PHAC_DISCLOOP_POS_BIT_MASK_B) == PHAC_DISCLOOP_POS_BIT_MASK_B)
            )
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->bEMVCoPropOpRfFieldReset = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_GT_ACTIVE_US:
        pDataParams->wActPollGTimeUs = wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_BAIL_OUT:
        if (0u != (wValue & ~(PHAC_DISCLOOP_POS_BIT_MASK_A |  PHAC_DISCLOOP_POS_BIT_MASK_B
            | PHAC_DISCLOOP_POS_BIT_MASK_F424 | PHAC_DISCLOOP_POS_BIT_MASK_F212
            | PHAC_DISCLOOP_POS_BIT_MASK_V | PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3)))
        {
            /* Invalid bail out option set */
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        pDataParams->bPasPollBailOut = (uint8_t) wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_OPE_MODE:
        if(!((wValue == RD_LIB_MODE_NFC) ||
            (wValue == RD_LIB_MODE_EMVCO) ||
            (wValue == RD_LIB_MODE_ISO)))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->bOpeMode = (uint8_t)wValue;
        PH_CHECK_SUCCESS_FCT(status, phhalHw_SetConfig(pDataParams->pHalDataParams, PHHAL_HW_CONFIG_OPE_MODE, wValue));
#ifdef NXPBUILD__PHPAL_I14443P4_SW
        PH_CHECK_SUCCESS_FCT(status, phpalI14443p4_SetConfig(pDataParams->pPal14443p4DataParams, PHPAL_I14443P4_CONFIG_OPE_MODE, wValue));
#endif /* NXPBUILD__PHPAL_I14443P4_SW */

#ifdef NXPBUILD__PHPAL_I14443P3B_SW
        PH_CHECK_SUCCESS_FCT(status, phpalI14443p3b_SetConfig(pDataParams->pPal1443p3bDataParams, PHPAL_I14443P3B_CONFIG_OPE_MODE, wValue));
#endif /* NXPBUILD__PHPAL_I14443P3B_SW */

#ifdef NXPBUILD__PHPAL_I14443P3A_SW
        PH_CHECK_SUCCESS_FCT(status, phpalI14443p3a_SetConfig(pDataParams->pPal1443p3aDataParams, PHPAL_I14443P3A_CONFIG_OPE_MODE, wValue));
#endif /* NXPBUILD__PHPAL_I14443P3A_SW */

#ifdef NXPBUILD__PHPAL_I14443P4A_SW
        PH_CHECK_SUCCESS_FCT(status, phpalI14443p4a_SetConfig(pDataParams->pPal1443p4aDataParams, PHPAL_I14443P4A_CONFIG_OPE_MODE, wValue));
#endif /* NXPBUILD__PHPAL_I14443P4A_SW */

#ifdef NXPBUILD__PHPAL_SLI15693_SW
        PH_CHECK_SUCCESS_FCT(status, phpalSli15693_SetConfig(pDataParams->pPalSli15693DataParams, PHPAL_SLI15693_CONFIG_OPE_MODE, wValue));
#endif /* NXPBUILD__PHPAL_SLI15693_SW */
        break;

    case PHAC_DISCLOOP_CONFIG_ENABLE_LPCD:
        pDataParams->bLpcdEnabled = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_EMVCO_PROF_FSCI_MAX:
        if ((wValue != 0x08) && (wValue != PH_NXPNFCRDLIB_CONFIG_DEFAULT_FSCI_VALUE))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->bFsciMax = (uint8_t)wValue;
        break;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT:
        if ((wValue & 0xFFU) > PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_A] = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_SLEEP_STATE:
        if (((wValue & 0xFFU) != PH_ON) && ((wValue & 0xFFU) != PH_OFF))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        bIndex = (uint8_t)((wValue & 0xFF00U) >> 8U);
        if (bIndex >= PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.aTypeA_I3P3[bIndex].bSleep = (uint8_t)(wValue & 0xFFU);
        break;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_FSDI:
        if (wValue > PHPAL_I14443P4_FRAMESIZE_MAX)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bFsdi = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_CID:
        if (wValue > PHAC_DISCLOOP_SW_I3P4_MAX_CID)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bCid = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_NAD:
        /* Valid NAD complaint with ISO/IEC 7816-3 shall be set by application. */
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bNad = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DRI:
        if ((wValue > PHAC_DISCLOOP_SW_I3P4_MAX_DRI) ||
            ((pDataParams->bOpeMode == RD_LIB_MODE_EMVCO) && (wValue != PHPAL_I14443P4A_DATARATE_106)))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDri = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DSI:
        if ((wValue > PHAC_DISCLOOP_SW_I3P4_MAX_DSI) ||
            ((pDataParams->bOpeMode == RD_LIB_MODE_EMVCO) && (wValue != PHPAL_I14443P4A_DATARATE_106)))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDsi = (uint8_t)wValue;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_DID:
        if (wValue > PHPAL_I18092MPI_DID_MAX)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bDid = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_LRI:
        if (wValue > PHPAL_I18092MPI_FRAMESIZE_254)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bLri = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_NAD_ENABLE:
        if (wValue == 0U)
        {
            pDataParams->sTypeATargetInfo.sTypeA_P2P.bNadEnable = PH_OFF;
        }
        else
        {
            pDataParams->sTypeATargetInfo.sTypeA_P2P.bNadEnable = PH_ON;
        }
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_NAD:
        if (wValue > 255U)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bNad = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_GI_LEN:
        if (wValue > PHPAL_I18092MPI_MAX_GI_LENGTH)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeATargetInfo.sTypeA_P2P.bGiLength = (uint8_t)wValue;
        break;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT:
    if ((wValue & 0xFFU) > PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
    }
    pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_B] = (uint8_t)wValue;
    break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_AFI_REQ:
      pDataParams->sTypeBTargetInfo.bAfiReq = (uint8_t)wValue;
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_EXTATQB:
      if (wValue == 0U)
      {
          pDataParams->sTypeBTargetInfo.bExtendedAtqBbit = 0;
      }
      else
      {
          pDataParams->sTypeBTargetInfo.bExtendedAtqBbit = 1;
      }
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_FSDI:
      if (wValue > PHPAL_I14443P3B_FRAMESIZE_MAX)
      {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
      }
      pDataParams->sTypeBTargetInfo.bFsdi = (uint8_t)wValue;
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_CID:
      if (wValue > PHAC_DISCLOOP_SW_I3P4_MAX_CID)
      {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
      }
      pDataParams->sTypeBTargetInfo.bCid = (uint8_t)wValue;
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_NAD:
        /* Valid NAD complaint with ISO/IEC 7816-3 shall be set by application. */
        pDataParams->sTypeBTargetInfo.bNad = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_DRI:
      if ((wValue > PHAC_DISCLOOP_SW_I3P4_MAX_DRI) ||
          ((pDataParams->bOpeMode == RD_LIB_MODE_EMVCO) && (wValue != PHPAL_I14443P3B_DATARATE_106)))
      {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
      }
      pDataParams->sTypeBTargetInfo.bDri = (uint8_t)wValue;
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_DSI:
      if ((wValue > PHAC_DISCLOOP_SW_I3P4_MAX_DSI) ||
          ((pDataParams->bOpeMode == RD_LIB_MODE_EMVCO) && (wValue != PHPAL_I14443P3B_DATARATE_106)))
      {
          return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
      }
      pDataParams->sTypeBTargetInfo.bDsi = (uint8_t)wValue;
      break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_SLEEP_STATE:
        if (((wValue & 0xFFU) != PH_ON) && ((wValue & 0xFFU) != PH_OFF))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        bIndex = (uint8_t)((wValue & 0xFF00U) >> 8U);
        if (bIndex >= PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bIndex].bSleep = (uint8_t)(wValue & 0xFFU);
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEF_CUR_BAUD:
        pDataParams->bFelicaBaud = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_DEVICE_LIMIT:
        if ((wValue & 0xFFU) > PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_F212] = (uint8_t)wValue;
        break;

#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS)  || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)
    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_DID:
        if (wValue > PHPAL_I18092MPI_DID_MAX)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        pDataParams->sTypeFTargetInfo.sTypeF_P2P.bDid = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_LRI:
        if (wValue > PHPAL_I18092MPI_FRAMESIZE_254)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeFTargetInfo.sTypeF_P2P.bLri = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_NAD_ENABLE:
        pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNadEnable = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_NAD:
        if (wValue > 255U)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNad = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_GI_LEN:
        if (wValue > PHPAL_I18092MPI_MAX_GI_LENGTH)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTypeFTargetInfo.sTypeF_P2P.bGiLength = (uint8_t)wValue;
        break;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEV_DEVICE_LIMIT:
        if ((wValue & 0xFFU) > PHAC_DISCLOOP_CFG_MAX_VICINITY_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_V] = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_RX_DATA_RATE:
        if((wValue != PHHAL_HW_RF_RX_DATARATE_HIGH)
           && (wValue != PHHAL_HW_RF_RX_DATARATE_LOW))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        /* Set request flag to indicate high data rate */
        if(wValue == PHHAL_HW_RF_RX_DATARATE_HIGH)
        {
            pDataParams->sTypeVTargetInfo.bFlag |= PHPAL_SLI15693_FLAG_DATA_RATE;
        }
        else
        {
            pDataParams->sTypeVTargetInfo.bFlag &= ~((uint8_t)PHPAL_SLI15693_FLAG_DATA_RATE);
        }
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_MODE:
        if((wValue != PHPAL_SLI15693_FLAG_ADDRESSED)
           && (wValue != PHPAL_SLI15693_FLAG_SELECTED) && (wValue != PHPAL_SLI15693_FLAG_NON_ADDRESSED))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }

        /* Save previous Flags value */
        PH_CHECK_SUCCESS_FCT(status, phpalSli15693_GetConfig(pDataParams->pPalSli15693DataParams, PHPAL_SLI15693_CONFIG_FLAGS, &wSliConfigFlags));

        if(wValue == PHPAL_SLI15693_FLAG_SELECTED)
        {
            /* Set the Select_flag and clear the Adress_flag */
            wSliConfigFlags |= PHPAL_SLI15693_FLAG_SELECTED;
            wSliConfigFlags &= (uint8_t)~(uint8_t)PHPAL_SLI15693_FLAG_ADDRESSED;
        }
        else if(wValue == PHPAL_SLI15693_FLAG_ADDRESSED)
        {
            /* Set the Adress_flag and clear the Select_flag */
            wSliConfigFlags |= PHPAL_SLI15693_FLAG_ADDRESSED;
            wSliConfigFlags &= (uint8_t)~(uint8_t)PHPAL_SLI15693_FLAG_SELECTED;
        }
        else
        {
            /* Clear both Adress_flag and Select_flag */
            wSliConfigFlags &= (uint8_t)~(uint8_t)PHPAL_SLI15693_FLAG_ADDRESSED;
            wSliConfigFlags &= (uint8_t)~(uint8_t)PHPAL_SLI15693_FLAG_SELECTED;
        }

        /* Update Flags value */
        PH_CHECK_SUCCESS_FCT(status, phpalSli15693_SetConfig(pDataParams->pPalSli15693DataParams, PHPAL_SLI15693_CONFIG_FLAGS, wSliConfigFlags));

        pDataParams->sTypeVTargetInfo.bMode = (uint8_t)wValue;
        break;

#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    case PHAC_DISCLOOP_CONFIG_18000P3M3_DEVICE_LIMIT:
        if ((wValue & 0xFFU) > PHAC_DISCLOOP_CFG_MAX_VICINITY_CARDS_SUPPORTED)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_18000P3M3] = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_I18000P3M3_MODULATION:
        if((wValue != PHPAL_I18000P3M3_M_MANCHESTER_2)
           && (wValue != PHPAL_I18000P3M3_M_MANCHESTER_4))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sI18000p3m3TargetInfo.bM = (uint8_t)wValue;
        break;

    case PHAC_DISCLOOP_CONFIG_I18000P3M3_FREQUENCY:
        if((wValue != PHPAL_I18000P3M3_LF_423KHZ)
           && (wValue != PHPAL_I18000P3M3_LF_847KHZ))
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sI18000p3m3TargetInfo.bDr = (uint8_t)wValue;
        break;

#endif /* NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TARGET
    case PHAC_DISCLOOP_CONFIG_TARGET_RETRY_COUNT:
        if (wValue > 255U)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
        }
        pDataParams->sTargetParams.bRetryCount = (uint8_t)wValue;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TARGET */

    default:
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
    }

    return status;
}

phStatus_t phacDiscLoop_Sw_GetConfig(
                                     phacDiscLoop_Sw_DataParams_t * pDataParams,
                                     uint16_t wConfig,
                                     uint16_t * pValue
                                     )
{
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;

    switch(wConfig)
    {
    case PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG:
        *pValue = pDataParams->bPasLisTechCfg;
        break;

    case PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG:
        *pValue = pDataParams->bActLisTechCfg;
        break;

    case PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG:
        *pValue = pDataParams->bActPollTechCfg;
        break;

    case PHAC_DISCLOOP_CONFIG_COLLISION_PENDING:
        *pValue = pDataParams->bCollPend;
        break;

    case PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE:
        *pValue = (uint8_t)pDataParams->bPollState;
        break;

    case PHAC_DISCLOOP_CONFIG_ANTI_COLL:
        *pValue = pDataParams->bUseAntiColl;
        break;

    case PHAC_DISCLOOP_CONFIG_TECH_DETECTED:
        *pValue = pDataParams->bDetectedTechs;
        break;

    case PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND:
        *pValue = pDataParams->bNumOfCards;
         break;

    case PHAC_DISCLOOP_CONFIG_BAIL_OUT:
        *pValue = pDataParams->bPasPollBailOut;
        break;

    case PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG:
        *pValue = pDataParams->bPasPollTechCfg;
        break;

    case PHAC_DISCLOOP_CONFIG_ENABLE_LPCD:
        *pValue = pDataParams->bLpcdEnabled;
        break;

    case PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO:
        *pValue = pDataParams->wErrorCode;
        break;

    case PHAC_DISCLOOP_CONFIG_GT_ACTIVE_US:
        *pValue = pDataParams->wActPollGTimeUs;
        break;

    case PHAC_DISCLOOP_CONFIG_EMVCO_PROF_FSCI_MAX:
        *pValue = pDataParams->bFsciMax;
        break;

    case PHAC_DISCLOOP_CONFIG_EMVCO_PROP_OP_RF_RESET:
        *pValue = pDataParams->bEMVCoPropOpRfFieldReset;
        break;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    case PHAC_DISCLOOP_CONFIG_GTA_VALUE_US:
        *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_A];
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_TAGS_FOUND:
        *pValue = pDataParams->sTypeATargetInfo.bTotalTagsFound;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT:
        *pValue = pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_A];
        break;

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_FSDI:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_I3P4.bFsdi;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_CID:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_I3P4.bCid;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_NAD:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_I3P4.bNad;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DSI:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDsi;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DRI:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_I3P4.bDri;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_DID:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bDid;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_LRI:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bLri;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_NAD_ENABLE:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bNadEnable;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_NAD:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bNad;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_GI_LEN:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bGiLength;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEA_P2P_ATR_RES_LEN:
        *pValue = pDataParams->sTypeATargetInfo.sTypeA_P2P.bAtrResLength;
        break;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    case PHAC_DISCLOOP_CONFIG_GTB_VALUE_US:
        *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_B];
        break;

     case PHAC_DISCLOOP_CONFIG_TYPEB_TAGS_FOUND:
        *pValue = pDataParams->sTypeBTargetInfo.bTotalTagsFound;
        break;

     case PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT:
        *pValue = pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_B];
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_SUPPORT_TYPE4B:
        *pValue = pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].bSupportType4B;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_DRI:
        *pValue = pDataParams->sTypeBTargetInfo.bDri;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEB_DSI:
        *pValue = pDataParams->sTypeBTargetInfo.bDsi;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    case PHAC_DISCLOOP_CONFIG_GTFB_VALUE_US:
         *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F212];
         break;

    case PHAC_DISCLOOP_CONFIG_GTBF_VALUE_US:
         *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_F424];
         break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_TAGS_FOUND:
        *pValue = pDataParams->sTypeFTargetInfo.bTotalTagsFound;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_DEVICE_LIMIT:
        *pValue = pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_F212];
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_CUR_BAUD:
         *pValue = pDataParams->bFelicaBaud;
         break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS */

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS)  || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)
    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_DID:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bDid;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_LRI:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bLri;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_NAD_ENABLE:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNadEnable;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_NAD:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bNad;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_GI_LEN:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bGiLength;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEF_P2P_ATR_RES_LEN:
        *pValue = pDataParams->sTypeFTargetInfo.sTypeF_P2P.bAtrResLength;
        break;
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    case PHAC_DISCLOOP_CONFIG_GTV_VALUE_US:
        *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_V];
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_DEVICE_LIMIT:
        *pValue = pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_V];
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_TAGS_FOUND:
        *pValue = pDataParams->sTypeVTargetInfo.bTotalTagsFound;
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_RX_DATA_RATE:
        if(0U != (pDataParams->sTypeVTargetInfo.bFlag & PHPAL_SLI15693_FLAG_DATA_RATE))
        {
            *pValue = PHHAL_HW_RF_RX_DATARATE_HIGH;
        }
        else
        {
            *pValue = PHHAL_HW_RF_RX_DATARATE_LOW;
        }
        break;

    case PHAC_DISCLOOP_CONFIG_TYPEV_MODE:
        *pValue = pDataParams->sTypeVTargetInfo.bMode;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    case PHAC_DISCLOOP_CONFIG_GT18000P3M3_VALUE_US:
        *pValue = pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_18000P3M3];
        break;

    case PHAC_DISCLOOP_CONFIG_18000P3M3_DEVICE_LIMIT:
        *pValue = pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_18000P3M3];
        break;

    case PHAC_DISCLOOP_CONFIG_18000P3M3_TAGS_FOUND:
        *pValue = pDataParams->sI18000p3m3TargetInfo.bTotalTagsFound;
        break;

    case PHAC_DISCLOOP_CONFIG_I18000P3M3_MODULATION:
        *pValue = pDataParams->sI18000p3m3TargetInfo.bM;
        break;

    case PHAC_DISCLOOP_CONFIG_I18000P3M3_FREQUENCY:
        *pValue = pDataParams->sI18000p3m3TargetInfo.bDr;
        break;

#endif /* NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS */

#ifdef NXPBUILD__PHAC_DISCLOOP_TARGET
    case PHAC_DISCLOOP_CONFIG_TARGET_RETRY_COUNT:
        *pValue = pDataParams->sTargetParams.bRetryCount;
        break;
#endif /* NXPBUILD__PHAC_DISCLOOP_TARGET */

    default:
        status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
    }

    return status;
}

phStatus_t phacDiscLoop_Sw_ActivateCard(
                                        phacDiscLoop_Sw_DataParams_t * pDataParams,
                                        uint8_t bTechType,
                                        uint8_t bTagIndex
                                        )
{
    return phacDiscLoop_Sw_Int_ActivateDevice(pDataParams, bTechType, bTagIndex);
}

phStatus_t phacDiscLoop_Sw_CfgPollSeq(
                                      phacDiscLoop_Sw_DataParams_t * pDataParams,
                                      uint8_t * pDiscloopCfgPollSeq
                                      )
{
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    uint8_t     PH_MEMLOC_REM bIndex;

    for (bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++)
    {
        if (pDiscloopCfgPollSeq[bIndex] >= PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED)
        {
            status = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
            break;
        }
    }

    if (bIndex == PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED)
    {
        pDataParams->pPasTechPollSeq = pDiscloopCfgPollSeq;
    }

    return status;
}
#endif  /* NXPBUILD__PHAC_DISCLOOP_SW */
