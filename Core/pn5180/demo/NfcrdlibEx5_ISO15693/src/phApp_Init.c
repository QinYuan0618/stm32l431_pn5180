/*----------------------------------------------------------------------------*/
/* Copyright 2016-2020,2022 NXP                                               */
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
* Example Source abstracting component data structure and code initialization and code specific to HW used in the examples
* This file shall be present in all examples. A customer does not need to touch/modify this file. This file
* purely depends on the phNxpBuild_Lpc.h or phNxpBuild_App.h
* The phAppInit.h externs the component data structures initialized here that is in turn included by the core examples.
* The core example shall not use any other variable defined here except the RdLib component data structures(as explained above)
* The RdLib component initialization requires some user defined data and function pointers.
* These are defined in the respective examples and externed here.
*
* Keystore and Crypto initialization needs to be handled by application.
*
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*
*/

/* Status header */
#include <ph_Status.h>

#include "phApp_Init.h"

/* LLCP header */
#include <phlnLlcp.h>

#include <phOsal.h>

#ifdef PH_PLATFORM_HAS_ICFRONTEND
#include "BoardSelection.h"
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

/*******************************************************************************
**   Function Declarations
*******************************************************************************/

phStatus_t phApp_Configure_IRQ();

/*******************************************************************************
**   Global Variable Declaration
*******************************************************************************/

#ifdef NXPBUILD__PHLN_LLCP_SW
phlnLlcp_Sw_DataParams_t           slnLlcp;            /* LLCP component */
#endif /* NXPBUILD__PHLN_LLCP_SW */

/* General information bytes to be sent with ATR Request */
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW)
uint8_t aLLCPGeneralBytes[36] = { 0x46,0x66,0x6D,
                                  0x01,0x01,0x10,       /*VERSION*/
                                  0x03,0x02,0x00,0x01,  /*WKS*/
                                  0x04,0x01,0xF1        /*LTO*/
                                 };
uint8_t   bLLCPGBLength = 13;
#endif

/* ATR Response or ATS Response holder */
#if defined(NXPBUILD__PHPAL_I14443P4A_SW)     || \
    defined(NXPBUILD__PHPAL_I18092MPI_SW)
uint8_t    aResponseHolder[64];
#endif

/*******************************************************************************
**   Function Definitions
*******************************************************************************/


#ifdef PH_PLATFORM_HAS_ICFRONTEND
/**
* This function will initialize Host Controller interfaced with NXP Reader IC's.
* Any initialization which is not generic across Platforms, should be done here.
* Note: For NXP NFC Controllers HOST initialization is not required.
*/
void phApp_CPU_Init(void)
{
#if defined PHDRIVER_KINETIS_K82
    phApp_K82_Init();
#elif defined(PHDRIVER_LPC1769) && defined(__CC_ARM)
    SystemCoreClock =  (( unsigned long ) 96000000);
#elif defined(PH_OSAL_LINUX) && defined(NXPBUILD__PHHAL_HW_PN5190)
    phStatus_t  status;
    status = PiGpio_OpenIrq();
    if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        DEBUG_PRINTF("\n PiGpio_OpenIrq failed \n");
        DEBUG_PRINTF("\n Couldn't open PN5190 Kernel IRQ Driver.\n Halting here!!FIX IT!!\n");
        while(1);
    }
#else
    /* In case of LPC series, startup file takes care of initializing clock and ports.
     * No initialization is required in Linux environment. */
#endif
}
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

/**
* This function will initialize Reader LIbrary Component
*/
phStatus_t phApp_Comp_Init(void * pDiscLoopParams)
{
    phStatus_t wStatus = PH_ERR_SUCCESS;
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)

    phacDiscLoop_Sw_DataParams_t * pDiscLoop = (phacDiscLoop_Sw_DataParams_t *)pDiscLoopParams;
#endif

/* Initialize the LLCP component */
#ifdef NXPBUILD__PHLN_LLCP_SW
    slnLlcp.sLocalLMParams.wMiu = 0x00; /* 128 bytes only */
    slnLlcp.sLocalLMParams.wWks = 0x11; /* SNEP & LLCP */
    slnLlcp.sLocalLMParams.bLto = 100; /* Maximum LTO */
    slnLlcp.sLocalLMParams.bOpt = 0x02;
    slnLlcp.sLocalLMParams.bAvailableTlv = PHLN_LLCP_TLV_MIUX_MASK | PHLN_LLCP_TLV_WKS_MASK |
        PHLN_LLCP_TLV_LTO_MASK | PHLN_LLCP_TLV_OPT_MASK;

    wStatus = phlnLlcp_Sw_Init(
        &slnLlcp,
        sizeof(phlnLlcp_Sw_DataParams_t),
        aLLCPGeneralBytes,
        &bLLCPGBLength);
#endif /* NXPBUILD__PHLN_LLCP_SW */

#ifdef NXPBUILD__PHAC_DISCLOOP_SW
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || defined(NXPBUILD__PHPAL_I18092MT_SW)
    /* Assign the GI for Type A */
    pDiscLoop->sTypeATargetInfo.sTypeA_P2P.pGi       = (uint8_t *)aLLCPGeneralBytes;
    pDiscLoop->sTypeATargetInfo.sTypeA_P2P.bGiLength = bLLCPGBLength;
    /* Assign the GI for Type F */
    pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.pGi       = (uint8_t *)aLLCPGeneralBytes;
    pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.bGiLength = bLLCPGBLength;
#endif

#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS) || defined(NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE)
    /* Assign ATR response for Type A */
    pDiscLoop->sTypeATargetInfo.sTypeA_P2P.pAtrRes   = aResponseHolder;
#endif
#if defined(NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS) ||  defined(NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE) || \
    defined(NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE)
    /* Assign ATR response for Type F */
    pDiscLoop->sTypeFTargetInfo.sTypeF_P2P.pAtrRes   = aResponseHolder;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
    /* Assign ATS buffer for Type A */
    pDiscLoop->sTypeATargetInfo.sTypeA_I3P4.pAts     = aResponseHolder;
#endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */
#endif /* NXPBUILD__PHAC_DISCLOOP_SW */
    return wStatus;
}

phStatus_t phApp_Configure_IRQ()
{
#ifdef PH_OSAL_LINUX
    phStatus_t  wStatus;
#endif /* PH_OSAL_LINUX */

#ifdef PH_PLATFORM_HAS_ICFRONTEND
#if !(defined(PH_OSAL_LINUX) && defined(NXPBUILD__PHHAL_HW_PN5190))
    phDriver_Pin_Config_t pinCfg;

    pinCfg.bOutputLogic = PH_DRIVER_SET_LOW;
    pinCfg.bPullSelect = PHDRIVER_PIN_IRQ_PULL_CFG;

    pinCfg.eInterruptConfig = PIN_IRQ_TRIGGER_TYPE;
    phDriver_PinConfig(PHDRIVER_PIN_IRQ, PH_DRIVER_PINFUNC_INTERRUPT, &pinCfg);
#endif

#ifdef PHDRIVER_LPC1769
    NVIC_SetPriority(EINT_IRQn, EINT_PRIORITY);
    /* Enable interrupt in the NVIC */
    NVIC_ClearPendingIRQ(EINT_IRQn);
    NVIC_EnableIRQ(EINT_IRQn);
#endif /* PHDRIVER_LPC1769 */

#ifdef PH_OSAL_LINUX

    gphPiThreadObj.pTaskName = (uint8_t *) "IrqPolling";
    gphPiThreadObj.pStackBuffer = NULL;
    gphPiThreadObj.priority = PI_IRQ_POLLING_TASK_PRIO;
    gphPiThreadObj.stackSizeInNum = PI_IRQ_POLLING_TASK_STACK;
    PH_CHECK_SUCCESS_FCT(wStatus, phOsal_ThreadCreate(&gphPiThreadObj.ThreadHandle, &gphPiThreadObj,
        &phExample_IrqPolling, NULL));

#endif /* PH_OSAL_LINUX */

#ifdef PHDRIVER_KINETIS_K82
    NVIC_SetPriority(EINT_IRQn, EINT_PRIORITY);
    NVIC_ClearPendingIRQ(EINT_IRQn);
    EnableIRQ(EINT_IRQn);
#endif /* PHDRIVER_KINETIS_K82 */

#endif /* #ifdef PH_PLATFORM_HAS_ICFRONTEND */

    return PH_ERR_SUCCESS;
}

#ifdef PH_OSAL_LINUX
/*
 * \brief: The purpose of this Thread is to detect RF signal from an External Peer .
 */
static void phExample_IrqPolling(void* param)
{
    uint8_t bgpioVal = 0;
    uint8_t bhighOrLow = 0;

#if defined(NXPBUILD__PHHAL_HW_RC663) || defined(NXPBUILD__PHHAL_HW_PN5180)
    if(PIN_IRQ_TRIGGER_TYPE ==  PH_DRIVER_INTERRUPT_RISINGEDGE)
    {
        bhighOrLow = 1;
    }

    while(PiGpio_read(PHDRIVER_PIN_IRQ, &bgpioVal) != PH_ERR_SUCCESS)
    {
        PiGpio_unexport(PHDRIVER_PIN_IRQ);
        PiGpio_export(PHDRIVER_PIN_IRQ);
        PiGpio_set_direction(PHDRIVER_PIN_IRQ, false);

        if(PIN_IRQ_TRIGGER_TYPE ==  PH_DRIVER_INTERRUPT_RISINGEDGE)
        {
            PiGpio_set_edge(PHDRIVER_PIN_IRQ, true, false);
        }
        else
        {
            PiGpio_set_edge(PHDRIVER_PIN_IRQ, false, true);
        }
    }

    /* Initial status: If pin is already Active, post an event. */
    if(bgpioVal == bhighOrLow)
    {
        CLIF_IRQHandler();
    }
#endif

    while(1)
    {
        /* Block forever for Raising Edge in PHDRIVER_PIN_IRQ. */
#if defined(NXPBUILD__PHHAL_HW_RC663) || defined(NXPBUILD__PHHAL_HW_PN5180)
        if(PiGpio_poll(PHDRIVER_PIN_IRQ, bhighOrLow, -1) == PH_ERR_SUCCESS)
#elif defined(NXPBUILD__PHHAL_HW_PN5190)
        if(PiGpio_Irq() == PH_ERR_SUCCESS)
#endif
        {
            CLIF_IRQHandler();
        }
        else
        {
            PiGpio_unexport(PHDRIVER_PIN_IRQ);

            PiGpio_export(PHDRIVER_PIN_IRQ);

            PiGpio_set_direction(PHDRIVER_PIN_IRQ, false);

            if(PIN_IRQ_TRIGGER_TYPE ==  PH_DRIVER_INTERRUPT_RISINGEDGE)
            {
                PiGpio_set_edge(PHDRIVER_PIN_IRQ, true, false);
            }
            else
            {
                PiGpio_set_edge(PHDRIVER_PIN_IRQ, false, true);
            }
        }

    }
}
#endif /* PH_OSAL_LINUX */

/******************************************************************************
**                            End Of File
******************************************************************************/
