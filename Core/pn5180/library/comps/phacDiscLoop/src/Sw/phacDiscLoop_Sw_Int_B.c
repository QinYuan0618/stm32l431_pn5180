/*----------------------------------------------------------------------------*/
/* Copyright 2014-2023 NXP                                                    */
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
* Discovery Loop Activities for Type B polling.
* $Author$
* $Revision$ (v07.13.00)
* $Date$

*/

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include <ph_RefDefs.h>
#include <phacDiscLoop.h>
#include <phpalI14443p3b.h>
#include <phpalI14443p4.h>

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
#include "phacDiscLoop_Sw_Int.h"
#include "phacDiscLoop_Sw_Int_B.h"

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
phStatus_t phacDiscLoop_Sw_DetTechTypeB(
                                        phacDiscLoop_Sw_DataParams_t *pDataParams
                                        )
{
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    uint8_t    PH_MEMLOC_COUNT bIndex;

    phStatus_t PH_MEMLOC_REM wStatus;

    pDataParams->sTypeBTargetInfo.bAfiReq = 0x00;
    pDataParams->sTypeBTargetInfo.bTotalTagsFound = 0;
    pDataParams->bCollPend &= (uint8_t)~(uint8_t)PHAC_DISCLOOP_POS_BIT_MASK_B;

    for(bIndex = 0U; bIndex < PHAC_DISCLOOP_CFG_MAX_CARDS_SUPPORTED; bIndex++)
    {
        /* Device is not in HLTB state */
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bIndex].bSleep = 0U;
    }

    /* WakeupB with number of slot as 0 */
    wStatus = phpalI14443p3b_WakeUpB(
        pDataParams->pPal1443p3bDataParams,
        0,
        pDataParams->sTypeBTargetInfo.bAfiReq,
        pDataParams->sTypeBTargetInfo.bExtendedAtqBbit,
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].aAtqB,
        &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].bAtqBLength);

    if(0u != (phacDiscLoop_Sw_Int_IsValidPollStatus(wStatus)))
    {
        if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
        {
            pDataParams->bCollPend |= PHAC_DISCLOOP_POS_BIT_MASK_B;
        }
        pDataParams->sTypeBTargetInfo.bTotalTagsFound++;
    }
    else
    {
        return wStatus;
    }

    return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_TECH_DETECTED, PH_COMP_AC_DISCLOOP);
#else
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */
}

phStatus_t phacDiscLoop_Sw_Int_CollisionResolutionB(
                                                    phacDiscLoop_Sw_DataParams_t * pDataParams
                                                    )
{
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    phStatus_t PH_MEMLOC_REM   status = PH_ERR_SUCCESS;
    uint8_t    PH_MEMLOC_REM   bCurrentSlotNum;
    uint8_t    PH_MEMLOC_REM   bCurrentDeviceCount;
    uint8_t    PH_MEMLOC_REM   bLastSlotReached;
    uint8_t    PH_MEMLOC_COUNT bNumOfSlots;
    uint8_t    PH_MEMLOC_COUNT bRetryCount;

    /* Collision_Pending = 1 and Device limit  = 0 */
    if((0U != ((pDataParams->bCollPend & PHAC_DISCLOOP_POS_BIT_MASK_B))) && ((pDataParams->baPasConDevLim[PHAC_DISCLOOP_TECH_TYPE_B] == 0x00U)))
    {
        pDataParams->sTypeBTargetInfo.bTotalTagsFound = 0;
        return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_NO_DEVICE_RESOLVED, PH_COMP_AC_DISCLOOP);
    }

    bRetryCount = 0;
    /* Symbol 0 */
    bNumOfSlots = 0;

    /* Apply Guard time. */
    PH_CHECK_SUCCESS_FCT(status, phhalHw_SetConfig(
        pDataParams->pHalDataParams,
        PHHAL_HW_CONFIG_POLL_GUARD_TIME_US,
        pDataParams->waPasPollGTimeUs[PHAC_DISCLOOP_TECH_TYPE_B]));

    /* Configure HW for the TypeB technology */
    PH_CHECK_SUCCESS_FCT(status, phhalHw_ApplyProtocolSettings(
        pDataParams->pHalDataParams,
        PHHAL_HW_CARDTYPE_ISO14443B));

    /* WakeupB with number of slot as 0 */
    status = phpalI14443p3b_WakeUpB(
        pDataParams->pPal1443p3bDataParams,
        bNumOfSlots,
        pDataParams->sTypeBTargetInfo.bAfiReq,
        pDataParams->sTypeBTargetInfo.bExtendedAtqBbit,
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].aAtqB,
        &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].bAtqBLength);

    if(PH_ERR_SUCCESS != (status & PH_ERR_MASK))
    {
        /* As per EMVCo 3.1, wait for at least Tmin retransmission in case of timeout error. */
        if (pDataParams->bOpeMode == RD_LIB_MODE_EMVCO)
        {
            if ((status & PH_ERR_MASK) == PH_ERR_COLLISION_ERROR)
            {
                pDataParams->bCollPend &= (uint8_t)~(uint8_t)PHAC_DISCLOOP_POS_BIT_MASK_B;

                /* Report Error to Application and Application will perform PICC Reset */
                return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_COLLISION_PENDING, PH_COMP_AC_DISCLOOP);
            }

            while (((status & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT) && (bRetryCount < PH_NXPNFCRDLIB_CONFIG_EMVCO_RETRYCOUNT))
            {
                bRetryCount++;
                /* Wait for at least Tmin retransmission delay. */
                PH_CHECK_SUCCESS_FCT(status, phhalHw_Wait(
                    pDataParams->pHalDataParams,
                    PHHAL_HW_TIME_MICROSECONDS,
                    PH_NXPNFCRDLIB_CONFIG_EMVCO_DEFAULT_RETRANSMISSION));

                status = phpalI14443p3b_WakeUpB(pDataParams->pPal1443p3bDataParams,
                    bNumOfSlots,
                    pDataParams->sTypeBTargetInfo.bAfiReq,
                    pDataParams->sTypeBTargetInfo.bExtendedAtqBbit,
                    pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].aAtqB,
                    &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[0].bAtqBLength);
            }

            pDataParams->bCollPend &= (uint8_t)~(uint8_t)PHAC_DISCLOOP_POS_BIT_MASK_B;
            /* Some error that can't be handled */
            PH_CHECK_SUCCESS(status);
        }
        else
        {
            /* Symbol 2 */
            /* No Response */
            if((status & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT)
            {
                return status;
            }
            else
            { /* Symbol 3 */
                if (pDataParams->baPasConDevLim[1] == 0x00U)
                {
                    pDataParams->sTypeBTargetInfo.bTotalTagsFound = 0;
                    /* Symbol 4 */
                    pDataParams->bCollPend |= PHAC_DISCLOOP_POS_BIT_MASK_B;
                    return status;
                }
            }
        }
    }

    while(bNumOfSlots <= PHAC_DISCLOOP_TYPEB_MAX_SLOT_NUM)
    {
        /* Symbol 5 */
        bCurrentSlotNum = 0;
        bCurrentDeviceCount = 0;
        bLastSlotReached = 0;
        pDataParams->sTypeBTargetInfo.bTotalTagsFound = 0;
        pDataParams->bCollPend &= (uint8_t)~(uint8_t)PHAC_DISCLOOP_POS_BIT_MASK_B;

        while(0U == bLastSlotReached)
        {
            /* Symbol 6: Slot is Empty */
            if((status & PH_ERR_MASK) != PH_ERR_IO_TIMEOUT)
            {
                /* Symbol 7: Validate SENSB_RES */
                if (status == PH_ERR_SUCCESS)
                {
                    /* Symbol 9 */
                    if(bCurrentDeviceCount > 0U)
                    {
                        /* Symbol 10 */
                        status = phpalI14443p3b_SetSerialNo(
                                    pDataParams->pPal1443p3bDataParams,
                                    pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound - (uint8_t)1U].aPupi
                                    );

                        PH_CHECK_ABORT_FCT(status, phpalI14443p3b_HaltB(pDataParams->pPal1443p3bDataParams));
                    }

                    /* Symbol 12 */
                    (void)memcpy(pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].aPupi,
                        &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].aAtqB[1],
                        PHAC_DISCLOOP_I3P3B_PUPI_LENGTH);

                    /* Symbol 11 */
                    pDataParams->sTypeBTargetInfo.bTotalTagsFound++;
                    bCurrentDeviceCount++;

                    /* Symbol 13 */
                    if (pDataParams->sTypeBTargetInfo.bTotalTagsFound >= pDataParams->baPasConDevLim[1])
                    {
                        pDataParams->bNumOfCards = pDataParams->sTypeBTargetInfo.bTotalTagsFound;

                        return PH_ERR_SUCCESS;
                    }
                }
                else
                {
                    /* Symbol 8 CollisionPend: 1*/
                    pDataParams->bCollPend |= PHAC_DISCLOOP_POS_BIT_MASK_B;
                }
            }

            /* Symbol 14 */
            bCurrentSlotNum++;

            /* Symbol 15 */
            if(bCurrentSlotNum < ((uint8_t)1U  << bNumOfSlots))
            {
                /* Symbol 25 */
                PH_CHECK_ABORT_FCT(status, phpalI14443p3b_SlotMarker(
                    pDataParams->pPal1443p3bDataParams,
                    (bCurrentSlotNum + 1U),
                    pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].aAtqB,
                    &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].bAtqBLength));
            }
            else
            {
                bLastSlotReached = 1;
                /* Symbol 16 */
                if (0U != (pDataParams->bCollPend & PHAC_DISCLOOP_POS_BIT_MASK_B))
                {
                    /* Symbol 17 */
                    if (pDataParams->sTypeBTargetInfo.bTotalTagsFound > 0U)
                    {
                        /* Symbol 20 */
                        if (pDataParams->sTypeBTargetInfo.bTotalTagsFound >= pDataParams->baPasConDevLim[1])
                        {
                            pDataParams->bNumOfCards = pDataParams->sTypeBTargetInfo.bTotalTagsFound;

                            return PH_ERR_SUCCESS;
                        }
                    }
                    else
                    {
                        /* Symbol 18 */
                        if (bNumOfSlots == PHAC_DISCLOOP_TYPEB_MAX_SLOT_NUM)
                        {
                            pDataParams->bNumOfCards = pDataParams->sTypeBTargetInfo.bTotalTagsFound;

                            if(pDataParams->sTypeBTargetInfo.bTotalTagsFound == 0U)
                            {
                                return PH_ADD_COMPCODE_FIXED(PHAC_DISCLOOP_NO_DEVICE_RESOLVED, PH_COMP_AC_DISCLOOP);
                            }

                            return PH_ERR_SUCCESS;
                        }

                        /* Symbol 19 */
                        bNumOfSlots++;
                    }

                    /* Symbol 21 */
                    if(bCurrentDeviceCount > 0U)
                    {
                        /* Symbol 22 */
                        PH_CHECK_ABORT_FCT(status, phpalI14443p3b_HaltB(pDataParams->pPal1443p3bDataParams));
                    }

                    /* Symbol 23 */
                    PH_CHECK_ABORT_FCT(status, phpalI14443p3b_RequestB(
                        pDataParams->pPal1443p3bDataParams,
                        bNumOfSlots,
                        pDataParams->sTypeBTargetInfo.bAfiReq,
                        pDataParams->sTypeBTargetInfo.bExtendedAtqBbit,
                        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].aAtqB,
                        &pDataParams->sTypeBTargetInfo.aTypeB_I3P3[pDataParams->sTypeBTargetInfo.bTotalTagsFound].bAtqBLength));
                }
                else
                {
                    pDataParams->bNumOfCards = pDataParams->sTypeBTargetInfo.bTotalTagsFound;

                    if(pDataParams->sTypeBTargetInfo.bTotalTagsFound == 0U)
                    {
                        return (PHAC_DISCLOOP_NO_DEVICE_RESOLVED | PH_COMP_AC_DISCLOOP);
                    }
                    return PH_ERR_SUCCESS;
                }
            }
        } /* while(!bLastSlotReached) */
    }

    pDataParams->bNumOfCards = pDataParams->sTypeBTargetInfo.bTotalTagsFound;

    if(pDataParams->sTypeBTargetInfo.bTotalTagsFound == 0U)
    {
        return (PHAC_DISCLOOP_NO_DEVICE_RESOLVED | PH_COMP_AC_DISCLOOP);
    }

    return PH_ERR_SUCCESS;
#else
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */
}

phStatus_t phacDiscLoop_Sw_Int_ActivateB(
                                         phacDiscLoop_Sw_DataParams_t * pDataParams,
                                         uint8_t bTypeBTagIdx
                                         )
{
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    uint8_t    PH_MEMLOC_REM bAtqbLen;
    uint8_t    PH_MEMLOC_BUF aAtqb[13];
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS
    uint8_t    PH_MEMLOC_REM bCidEnabled;
    uint8_t    PH_MEMLOC_REM bCid;
    uint8_t    PH_MEMLOC_REM bNadSupported;
    uint8_t    PH_MEMLOC_REM bFwi;
    uint8_t    PH_MEMLOC_REM bFsdi;
    uint8_t    PH_MEMLOC_REM bFsci;
    uint8_t    PH_MEMLOC_REM bBitRateCapability;
    uint8_t    PH_MEMLOC_REM bAtqb_Dsi;
    uint8_t    PH_MEMLOC_REM bAtqb_Dri;
    uint8_t    PH_MEMLOC_REM bDsi;
    uint8_t    PH_MEMLOC_REM bDri;
    uint16_t   PH_MEMLOC_REM wDataRate;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS */

    /* Only deviation form Device Activation Activity is
     * Device sleep state is not been check and always send WakeUpB Command
     */
    if (bTypeBTagIdx >= pDataParams->sTypeBTargetInfo.bTotalTagsFound)
    {
        /* Out of range or no such card found yet */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_AC_DISCLOOP);
    }

    /* Send WUPB for tags in sleep state (except the last detected tag all are
     * in sleep state) */
    if ( (bTypeBTagIdx < (pDataParams->sTypeBTargetInfo.bTotalTagsFound - (uint8_t)1U) ) ||
                (pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bSleep == 1U)
                )
    {
        PH_CHECK_ABORT_FCT(status, phpalI14443p3b_WakeUpB(
            pDataParams->pPal1443p3bDataParams,
            0x00,
            pDataParams->sTypeBTargetInfo.bAfiReq,
            pDataParams->sTypeBTargetInfo.bExtendedAtqBbit,
            aAtqb,
            &bAtqbLen));
    }

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS
    /* AttriB: activate PICC */

    /* Enable Emd check */
    PH_CHECK_SUCCESS_FCT(status, phhalHw_SetConfig(pDataParams->pHalDataParams, PHHAL_HW_CONFIG_SET_EMD, PH_ON));

    pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bSupportType4B = PH_OFF;
    if (0u != ((pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].aAtqB[PHAC_DISCLOOP_TYPEB_PROTOCOL_TYPE_OFFSET] & PHAC_DISCLOOP_TYPEB_MASK_PROTOCOL_TYPE)))
    {
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bSupportType4B = PH_ON;
    }

    if (((pDataParams->bOpeMode == RD_LIB_MODE_ISO) || (pDataParams->bOpeMode == RD_LIB_MODE_NFC)) &&
        (pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bSupportType4B == PH_OFF))
    {
        return PH_ERR_SUCCESS;
    }

    bBitRateCapability = pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].aAtqB[9U];
    bDsi = pDataParams->sTypeBTargetInfo.bDsi;
    bDri = pDataParams->sTypeBTargetInfo.bDri;
    /* Check user parameter change request versus Card bit rate capabilities and update DR and DS if required. */
    if (((bDsi != PHPAL_I14443P3B_DATARATE_106) || (bDri != PHPAL_I14443P3B_DATARATE_106)) &&
        ((bBitRateCapability & 0x08U) == 0x00))
    {
        if (bBitRateCapability & 0x40U)
        {
            bAtqb_Dsi = PHPAL_I14443P3B_DATARATE_848;
        }
        else if (bBitRateCapability & 0x20U)
        {
            bAtqb_Dsi = PHPAL_I14443P3B_DATARATE_424;
        }
        else if (bBitRateCapability & 0x10U)
        {
            bAtqb_Dsi = PHPAL_I14443P3B_DATARATE_212;
        }
        else
        {
            bAtqb_Dsi = PHPAL_I14443P3B_DATARATE_106;
        }

        if (bBitRateCapability & 0x04U)
        {
            bAtqb_Dri = PHPAL_I14443P3B_DATARATE_848;
        }
        else if (bBitRateCapability & 0x02U)
        {
            bAtqb_Dri = PHPAL_I14443P3B_DATARATE_424;
        }
        else if (bBitRateCapability & 0x01U)
        {
            bAtqb_Dri = PHPAL_I14443P3B_DATARATE_212;
        }
        else
        {
            bAtqb_Dri = PHPAL_I14443P3B_DATARATE_106;
        }

        if ((bDsi != bAtqb_Dsi) && (bDsi > bAtqb_Dsi))
        {
            bDsi = bAtqb_Dsi;
        }

        if ((bDri != bAtqb_Dri) && (bDri > bAtqb_Dri))
        {
            bDri = bAtqb_Dri;
        }

        if (bBitRateCapability & 0x80U)
        {
            /* Only same bit rate allowed in both directions. */
            if (bDsi != bDri)
            {
                (bDsi < bDri) ? (bDri = bDsi) : (bDsi = bDri);
            }
        }
    }

    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3b_Attrib(
        pDataParams->pPal1443p3bDataParams,
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].aAtqB,
        pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bAtqBLength,
        pDataParams->sTypeBTargetInfo.bFsdi,
        pDataParams->sTypeBTargetInfo.bCid,
        bDri,
        bDsi,
        &pDataParams->sTypeBTargetInfo.sTypeB_I3P4.bMbli));

    if (pDataParams->bOpeMode != RD_LIB_MODE_EMVCO)
    {
        /* Update Dri and Dsi parameters with currently applied values. */
        PH_CHECK_SUCCESS_FCT(status, phpalI14443p3b_GetConfig(
            pDataParams->pPal1443p3bDataParams,
            PHPAL_I14443P3B_CONFIG_DRI,
            &wDataRate));
        pDataParams->sTypeBTargetInfo.bDri = (uint8_t)wDataRate;

        PH_CHECK_SUCCESS_FCT(status, phpalI14443p3b_GetConfig(
            pDataParams->pPal1443p3bDataParams,
            PHPAL_I14443P3B_CONFIG_DSI,
            &wDataRate));
        pDataParams->sTypeBTargetInfo.bDsi = (uint8_t)wDataRate;
    }

    /* Retrieve 14443-3b protocol parameter */
    PH_CHECK_SUCCESS_FCT(status, phpalI14443p3b_GetProtocolParams(
        pDataParams->pPal1443p3bDataParams,
        &bCidEnabled,
        &bCid,
        &bNadSupported,
        &bFwi,
        &bFsdi,
        &bFsci));

    /* EMVCo v3.1: Limit the FSCI value to be used based on the RdLib execution environment. */
    if (pDataParams->bOpeMode == RD_LIB_MODE_EMVCO)
    {
        if (bFsci > pDataParams->bFsciMax)
        {
            bFsci = pDataParams->bFsciMax;
        }
    }

    /* Set 14443-4 protocol parameter */
    status = phpalI14443p4_SetProtocol(
        pDataParams->pPal14443p4DataParams,
        bCidEnabled,
        bCid,
        bNadSupported,
        pDataParams->sTypeBTargetInfo.bNad,
        bFwi,
        bFsdi,
        bFsci);

#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS */

    pDataParams->sTypeBTargetInfo.aTypeB_I3P3[bTypeBTagIdx].bSleep = 0U;
    return status;
#else
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AC_DISCLOOP);
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS */
}
#endif /* NXPBUILD__PHAC_DISCLOOP_SW */
