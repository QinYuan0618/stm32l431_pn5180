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
* Example Source for NfcrdlibEx1_DiscoveryLoop that uses the Discovery loop implementation.
* By default Discovery Loop will work as per NFC Forum Activity Specification v2.2
* which will configure the Reader in both POLL and LISTEN (only for Universal device)
* modes of discovery loop.Displays detected tag information(like UID, SAK, Product Type)
* and prints information when it gets activated as a target by an external Initiator/reader.
*
* By enabling "ENABLE_DISC_CONFIG" macro, few of the most common Discovery Loop configuration
* are been updated to values defined in this Example.
* By enabling "ENABLE_EMVCO_PROF", Discovery Loop will be configured as per EMVCo Polling
* specification else the Discovery Loop will still be configured to NFC Forum but user defined
* values as per this Application.
*
* NFC Forum Mode: Whenever multiple technologies are detected, example will select first
* detected technology to resolve. Example will activate device at index zero whenever multiple
* device is detected.
*
* For EMVCo profile, this example provide full EMVCo digital demonstration along with option to
* use different SELECT PPSE Commands.
*
* Please refer Readme.txt file for Hardware Pin Configuration, Software Configuration and steps to build and
* execute the project which is present in the same project directory.
*
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*/

/**
* Reader Library Headers
*/
#include "phApp_Init.h"
#include "phhalHw.h"
#include "stm32l4xx.h"

/* Local headers */
#include <phOsal.h>
#include "NfcrdlibEx1_DiscoveryLoop.h"
#include "NfcrdlibEx1_EmvcoProfile.h"
#include "phhalHw_Pn5180_Reg.h"
#include "phhalHw_Pn5180_Instr.h"
#include "emv_transaction.h"  // 获取卡基本信息并打印
#include "emv_payment_flow.h" // 卡交易支付流程

/* defines */
#define PH_OSAL_NULLOS         1
#define ENABLE_DISC_CONFIG	// 1
#define NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS  // 支持ISO14443A
#define NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS  // 支持ISO15693
/*******************************************************************************
**   Definitions
*******************************************************************************/

phacDiscLoop_Sw_DataParams_t       * pDiscLoop;       /* Discovery loop component */
phalMful_Sw_DataParams_t           * palMful;       /* Pointer to AL MFUL data-params */

#ifdef NXPBUILD__PHHAL_HW_TARGET
/*The below variables needs to be initialized according to example requirements by a customer */
uint8_t  sens_res[2]     = {0x04, 0x00};              /* ATQ bytes - needed for anti-collision */
uint8_t  nfc_id1[3]      = {0xA1, 0xA2, 0xA3};        /* user defined bytes of the UID (one is hardcoded) - needed for anti-collision */
uint8_t  sel_res         =  0x40;
uint8_t  nfc_id3         =  0xFA;                     /* NFC3 byte - required for anti-collision */
uint8_t  poll_res[18]    = {0x01, 0xFE, 0xB2, 0xB3, 0xB4, 0xB5,
                            0xB6, 0xB7, 0xC0, 0xC1, 0xC2, 0xC3,
                            0xC4, 0xC5, 0xC6, 0xC7, 0x23, 0x45 };
#endif /* NXPBUILD__PHHAL_HW_TARGET */

#ifdef PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION
uint32_t aDiscTaskBuffer[DISC_DEMO_TASK_STACK];
#else /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
#define aDiscTaskBuffer    NULL
#endif /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */

#ifdef PH_OSAL_FREERTOS
const uint8_t bTaskName[configMAX_TASK_NAME_LEN] = {"DiscLoop"};
#else
const uint8_t bTaskName[] = {"DiscLoop"};
#endif /* PH_OSAL_FREERTOS */
void TestRFField(void);
/*******************************************************************************
**   Static Defines
*******************************************************************************/

/* This is used to save restore Poll Config.
 * If in case application has update/change PollCfg to resolve Tech
 * when Multiple Tech was detected in previous poll cycle
 */
static uint16_t bSavePollTechCfg;
static volatile uint8_t bInfLoop = 1U;

/*******************************************************************************
**   Prototypes
*******************************************************************************/

void DiscoveryLoop_Demo(void  *pDataParams);
uint16_t NFCForumProcess(uint16_t wEntryPoint, phStatus_t DiscLoopStatus);

#ifdef ENABLE_DISC_CONFIG
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile);
#endif /* ENABLE_DISC_CONFIG */

/*******************************************************************************
**   Code
*******************************************************************************/

int nfc_discovery_main(void)
{
    do
    {
        phStatus_t status = PH_ERR_INTERNAL_ERROR;
        phNfcLib_Status_t     dwStatus;
#ifdef PH_PLATFORM_HAS_ICFRONTEND
        phNfcLib_AppContext_t AppContext = {0};
#endif /* PH_PLATFORM_HAS_ICFRONTEND */

#ifndef PH_OSAL_NULLOS
        phOsal_ThreadObj_t DiscLoop;
#endif /* PH_OSAL_NULLOS */

        /* 1.CPU初始化：Perform Controller specific initialization. */
        phApp_CPU_Init();

        /* Perform OSAL Initialization. */
//        (void)phOsal_Init(); // STM32的HAL_Ini()中已经配置了Systick，通过HAL_InitTick()，不需要OSAL的定时器

        DEBUG_PRINTF("\n[DiscoveryLoop]: \n");

        /* 3.IC前端初始化 */
#ifdef PH_PLATFORM_HAS_ICFRONTEND
        status = phbalReg_Init(&sBalParams, sizeof(phbalReg_Type_t));
        CHECK_STATUS(status);

        AppContext.pBalDataparams = &sBalParams;
        dwStatus = phNfcLib_SetContext(&AppContext);
        CHECK_NFCLIB_STATUS(dwStatus);
#endif

        /* 4.初始化NFC库：Initialize library */
        dwStatus = phNfcLib_Init();
        CHECK_NFCLIB_STATUS(dwStatus);
        if(dwStatus != PH_NFCLIB_STATUS_SUCCESS) break;

        /* 5. 获取关键组件指针：Set the generic pointer */
        pHal = phNfcLib_GetDataParams(PH_COMP_HAL);			// 硬件抽象层
        pDiscLoop = phNfcLib_GetDataParams(PH_COMP_AC_DISCLOOP);	// Discovery Loop 组件

        /* 6.初始化其他组件：Initialize other components that are not initialized by NFCLIB and configure Discovery Loop. */
        status = phApp_Comp_Init(pDiscLoop);
        CHECK_STATUS(status);
        if(status != PH_ERR_SUCCESS) break;

        /* 7.配置中断：Perform Platform Init */
        status = phApp_Configure_IRQ();
        CHECK_STATUS(status);
        if(status != PH_ERR_SUCCESS) break;

#ifndef PH_OSAL_NULLOS

        DiscLoop.pTaskName = (uint8_t *)bTaskName;
        DiscLoop.pStackBuffer = aDiscTaskBuffer;
        DiscLoop.priority = DISC_DEMO_TASK_PRIO;
        DiscLoop.stackSizeInNum = DISC_DEMO_TASK_STACK;
        phOsal_ThreadCreate(&DiscLoop.ThreadHandle, &DiscLoop, &DiscoveryLoop_Demo, pDiscLoop);

        phOsal_StartScheduler();

        DEBUG_PRINTF("RTOS Error : Scheduler exited. \n");
#else
        /* 8.启动DiscoveryLoop主任务 */
        (void)DiscoveryLoop_Demo(pDiscLoop);
#endif
    } while(0);

    while(bInfLoop); /* Comes here if initialization failure or scheduler exit due to error */

    return 0;
}

/**
* This function demonstrates the usage of discovery loop.
* The discovery loop can run with default setting Or can be configured as demonstrated and
* is used to detects and reports the NFC technology type.
* 用于持续检测是否有NFC标签进入天线区域，并报告检测到的NFC技术类型
* \param   pDataParams      The discovery loop data parameters
* \note    This function will never return
*/
void DiscoveryLoop_Demo(void  *pDataParams)
{
    phStatus_t    status, statustmp;
    uint16_t      wEntryPoint;
    phacDiscLoop_Profile_t bProfile = PHAC_DISCLOOP_PROFILE_UNKNOWN;

    /* This call shall allocate secure context before calling any secure function,
     * when FreeRtos trust zone is enabled.
     * */
//    phOsal_ThreadSecureStack( 512 ); // 这是FreeRTOS Trust Zone相关的，裸机不需要

    DEBUG_PRINTF("Entering Discovery Loop Demo...\r\n");

/* 1.加载预设的配置profile, 根据bProfile是NFC Forum和EMVCo, 设置不同的发现策略（调制方式、协议栈使用）*/
#ifdef ENABLE_DISC_CONFIG

#ifndef ENABLE_EMVCO_PROF
    bProfile = PHAC_DISCLOOP_PROFILE_NFC;
#else
    bProfile = PHAC_DISCLOOP_PROFILE_EMVCO;
#endif
    /* Load selected profile for Discovery loop */
    LoadProfile(bProfile);
#endif /* ENABLE_DISC_CONFIG */

/* 确保初始化PN5180芯片用于监听模式的参数设置正确 */
#ifdef NXPBUILD__PHHAL_HW_TARGET	// 启用了底层HAL硬件目标平台的支持(PN5180)
    /* Initialize the setting for Listen Mode */
    status = phApp_HALConfigAutoColl();
    CHECK_STATUS(status);
#endif /* NXPBUILD__PHHAL_HW_TARGET */

    /* 2.获取当前的轮询技术支持（例如启用了14443A、15693等）Get Poll Configuration */
    status = phacDiscLoop_GetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, &bSavePollTechCfg);
    CHECK_STATUS(status);

    /* 3.设置为轮询而不是监听 Start in poll mode */
    wEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
    status = PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED;

    /* 4. 关闭射频场，准备进行新一轮发现（防止错误识别）Switch off RF field */
    statustmp = phhalHw_FieldOff(pHal);
    CHECK_STATUS(statustmp);
//1    DEBUG_PRINTF("RF Field OFF status: 0x%04X\r\n", statustmp);

//1    TestRFField();

    while(1)
    {
    	DEBUG_PRINTF("Poll cycle start...\r\n");

        /* 每一次轮询开始前将轮询状态设为"检测中"，有些场景中如果上一次卡片未移除，需设置成"removal"状态
         * Before polling set Discovery Poll State to Detection , as later in the code it can be changed to e.g. PHAC_DISCLOOP_POLL_STATE_REMOVAL*/
        statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
        CHECK_STATUS(statustmp);

        /* 可以选择是否启用LPCD（低功耗卡检测）*/
#if !defined(ENABLE_EMVCO_PROF) && defined(PH_EXAMPLE1_LPCD_ENABLE)

#ifdef NXPBUILD__PHHAL_HW_RC663
        if (wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL)
#else
        /* Configure LPCD */
        if ((status & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED)
#endif
        {
            status = phApp_ConfigureLPCD();
            CHECK_STATUS(status);
        }

        /* Bool to enable LPCD feature. */
        status = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_ON);
        CHECK_STATUS(status);
#endif /* PH_EXAMPLE1_LPCD_ENABLE*/

        /* 启动轮询核心函数
         * Start discovery loop */
        /* PROGRAM BLOCK HERE at first, problem is solved */
        status = phacDiscLoop_Run(pDataParams, wEntryPoint);
        /* 输出：0x4080  或者  0x4083, 是否表示错误? 成功检测到卡返回0x408B */
        DEBUG_PRINTF("Discovery result: 0x%04X\r\n", status);

        /* ========== EMV交易处理集成点 ========== */
        if((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED)
        {
            DEBUG_PRINTF("Card activated, checking EMV compatibility\r\n");

            /* 检查是否为EMV兼容卡片 */
            if (EMV_IsEMVCompatibleCard(pDataParams))
            {
                DEBUG_PRINTF("=== EMV Compatible Card Detected, Starting Transaction ===\r\n");

                /* 执行EMV交易流程 */
                EMV_Result_t emv_result = EMV_ProcessPaymentFlow(pDataParams, 1000, 0x0156); // 10元人民币

                if (emv_result == EMV_SUCCESS) {
                    DEBUG_PRINTF("=== EMV Payment Flow Complete Successfully ===\r\n");
                } else {
                    DEBUG_PRINTF("=== EMV Payment Flow Failed, Error Code: %d ===\r\n", emv_result);
                }

                /* 等待卡片移除后继续循环 */
                EMV_WaitForCardRemoval(pDataParams);

                /* 继续下一次轮询 */
                continue;
            }
            else
            {
                DEBUG_PRINTF("Non-EMV card, using original processing flow\r\n");
            }
        }
        /* ========== EMV交易处理集成点结束 ========== */

        if(bProfile == PHAC_DISCLOOP_PROFILE_EMVCO)
        {
#if defined(ENABLE_EMVCO_PROF)
            EmvcoProfileProcess(pDataParams, status);
#endif /* ENABLE_EMVCO_PROF */
        }
        else
        {
            wEntryPoint = NFCForumProcess(wEntryPoint, status);

            /* 恢复轮询设置 Set Poll Configuration */
            statustmp = phacDiscLoop_SetConfig(pDataParams, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, bSavePollTechCfg);
            CHECK_STATUS(statustmp);

            /* 关闭RF场 Switch off RF field */
            statustmp = phhalHw_FieldOff(pHal);
            CHECK_STATUS(statustmp);

            /* 等待场关闭完成 Wait for field-off time-out */
            statustmp = phhalHw_Wait(pHal, PHHAL_HW_TIME_MICROSECONDS, 5100);
            CHECK_STATUS(statustmp);	// error

            DEBUG_PRINTF("Poll cycle complete, waiting...\r\n");
            HAL_Delay(1000);  // 1秒延时，方便观察
        }
    }
}

/* 应用层主逻辑处理函数：
 * 1.输出识别到的卡信息
 * 2.执行冲突解决和卡激活
 * 3.决定下一个入口点（轮询Poll 或 监听Listen）
 */
uint16_t NFCForumProcess(uint16_t wEntryPoint, phStatus_t DiscLoopStatus)
{
    phStatus_t    status;
    uint16_t      wTechDetected = 0;
    uint16_t      wNumberOfTags = 0;
    uint16_t      wValue;
    uint8_t       bIndex;
    uint16_t      wReturnEntryPoint;

    // 轮询POLL
    if(wEntryPoint == PHAC_DISCLOOP_ENTRY_POINT_POLL)
    {
    	/* 1.检测到多个技术，选择其中一个，配置冲突解决状态，重新执行POLL */
        if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_TECH_DETECTED)
        {
            DEBUG_PRINTF (" \n Multiple technology detected: \n");

            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
            CHECK_STATUS(status);

            if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_A))
            {
                DEBUG_PRINTF (" \tType A detected... \n");
            }
            if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_B))
            {
                DEBUG_PRINTF (" \tType B detected... \n");
            }
            if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_F212))
            {
                DEBUG_PRINTF (" \tType F detected with baud rate 212... \n");
            }
            if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_F424))
            {
                DEBUG_PRINTF (" \tType F detected with baud rate 424... \n");
            }
            if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_V))
            {
                DEBUG_PRINTF(" \tType V / ISO 15693 / T5T detected... \n");
            }

            /* Select 1st Detected Technology to Resolve*/
            for(bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++)
            {
                if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, (1 << bIndex)))
                {
                    /* Configure for one of the detected technology */
                    status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, (1 << bIndex));
                    CHECK_STATUS(status);
                    break;
                }
            }

            /* Print the technology resolved */
            phApp_PrintTech((1 << bIndex));

            /* Set Discovery Poll State to collision resolution */
            status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_COLLISION_RESOLUTION);
            CHECK_STATUS(status);

            /* Restart discovery loop in poll mode from collision resolution phase */
            DiscLoopStatus = phacDiscLoop_Run(pDiscLoop, wEntryPoint);
        }

        /* 2. 解决了多个设备，获取tag数量、技术类型，激活其中一个卡 */
        if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MULTI_DEVICES_RESOLVED)
        {
            /* Get Detected Technology Type */
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
            CHECK_STATUS(status);

            /* Get number of tags detected */
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
            CHECK_STATUS(status);

            DEBUG_PRINTF (" \n Multiple cards resolved: %d cards \n",wNumberOfTags);
            phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);

            if(wNumberOfTags > 1)
            {
                /* Get 1st Detected Technology and Activate device at index 0 */
                for(bIndex = 0; bIndex < PHAC_DISCLOOP_PASS_POLL_MAX_TECHS_SUPPORTED; bIndex++)
                {
                    if(PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, (1 << bIndex)))
                    {
                        DEBUG_PRINTF("\t Activating one card...\n");
                        status = phacDiscLoop_ActivateCard(pDiscLoop, bIndex, 0);
                        break;
                    }
                }

                if(((status & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED) ||
                        ((status & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED) ||
                        ((status & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND))
                {
                    /* Get Detected Technology Type */
                    status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
                    CHECK_STATUS(status);

                    phApp_PrintTagInfo(pDiscLoop, 0x01, wTechDetected);
                }
                else
                {
                    PRINT_INFO("\t\tCard activation failed...\n");
                }
            }
            /* Switch to LISTEN mode after POLL mode */
        }
        else if (((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_NO_TECH_DETECTED) ||
                ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_NO_DEVICE_RESOLVED))
        {
            /* Switch to LISTEN mode after POLL mode */
        }
        else if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFON)
        {
            /*
             * If external RF is detected during POLL, return back so that the application
             * can restart the loop in LISTEN mode
             */
        }
        else if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_MERGED_SEL_RES_FOUND)
        {
            DEBUG_PRINTF (" \n Device having T4T and NFC-DEP support detected... \n");

            /* Get Detected Technology Type */
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
            CHECK_STATUS(status);

            phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);

        /* Switch to LISTEN mode after POLL mode */
        }
        else if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_DEVICE_ACTIVATED)
        {
            DEBUG_PRINTF (" \n Card detected and activated successfully... \n");
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NR_TAGS_FOUND, &wNumberOfTags);
            CHECK_STATUS(status);

            /* Get Detected Technology Type */
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
            CHECK_STATUS(status);

            phApp_PrintTagInfo(pDiscLoop, wNumberOfTags, wTechDetected);

            /* Switch to LISTEN mode after POLL mode */
        }
        else if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVE_TARGET_ACTIVATED)
        {
            DEBUG_PRINTF (" \n Active target detected... \n");

            /* Switch to LISTEN mode after POLL mode */
        }
        else if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_PASSIVE_TARGET_ACTIVATED)
        {
            DEBUG_PRINTF (" \n Passive target detected... \n");

            /* Get Detected Technology Type */
            status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);
            CHECK_STATUS(status);

            phApp_PrintTagInfo(pDiscLoop, 1, wTechDetected);

            /* Switch to LISTEN mode after POLL mode */
        }
        else if ((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_LPCD_NO_TECH_DETECTED)
        {
            /* LPCD is succeed but no tag is detected. */
        }
        else
        {
            if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE)
            {
                status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
                CHECK_STATUS(status);
                DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
            }
            else
            {
                DEBUG_ERROR_PRINT(PrintErrorInfo(status));
            }
        }

        /* Update the Entry point to LISTEN mode. */
        wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;

    }
    else
    {
        if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_EXTERNAL_RFOFF)
        {
            /*
             * Enters here if in the target/card mode and external RF is not available
             * Wait for LISTEN timeout till an external RF is detected.
             * Application may choose to go into standby at this point.
             */
            status = phhalHw_EventConsume(pHal);
            CHECK_STATUS(status);

            status = phhalHw_SetConfig(pHal, PHHAL_HW_CONFIG_RFON_INTERRUPT, PH_ON);
            CHECK_STATUS(status);

            status = phhalHw_EventWait(pHal, LISTEN_PHASE_TIME_MS);
            if((status & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT)
            {
                wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
            }
            else
            {
                wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_LISTEN;
            }
        }
        else
        {
            if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_ACTIVATED_BY_PEER)
            {
                DEBUG_PRINTF (" \n Device activated in listen mode... \n");
            }
            else if ((DiscLoopStatus & PH_ERR_MASK) == PH_ERR_INVALID_PARAMETER)
            {
                /* In case of Front end used is RC663, then listen mode is not supported.
                 * Switch from listen mode to poll mode. */
            }
            else
            {
                if((DiscLoopStatus & PH_ERR_MASK) == PHAC_DISCLOOP_FAILURE)
                {
                    status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ADDITIONAL_INFO, &wValue);
                    CHECK_STATUS(status);
                    DEBUG_ERROR_PRINT(PrintErrorInfo(wValue));
                }
                else
                {
                    DEBUG_ERROR_PRINT(PrintErrorInfo(status));
                }
            }

            /* On successful activated by Peer, switch to LISTEN mode */
            wReturnEntryPoint = PHAC_DISCLOOP_ENTRY_POINT_POLL;
        }
    }
    return wReturnEntryPoint;
}

#ifdef ENABLE_DISC_CONFIG
/**
* This function will load/configure Discovery loop with default values based on interested profile
* Application can read these values from EEPROM area and load/configure Discovery loop via SetConfig
* 根据给定的NFC 配置 profile（如 NFC Forum 或 EMVCo）为 Discovery Loop 加载默认的轮询参数、通信协议支持位图、超时设置等
* \param   bProfile      Reader Library Profile
* \note    Values used below are default and is for demonstration purpose.
*/
static phStatus_t LoadProfile(phacDiscLoop_Profile_t bProfile)
{
    phStatus_t status = PH_ERR_SUCCESS;
    uint16_t   wPasPollConfig = 0;	// 被动轮询技术掩码（如TypeA/B/F/V）
    uint16_t   wActPollConfig = 0;	// 主动轮询技术掩码（如P2P 106/212/424kbps）
    uint16_t   wPasLisConfig = 0;	// 被动监听模式支持（当设备作为被动Tag）
    uint16_t   wActLisConfig = 0;	// 主动监听模式支持（设备作为主动P2P目标）

/* 1.通过一系列#ifdef宏, 构建这几个变量的位图. 即哪些协议被支持, 就把对应的bit位置为1 */
/* 1.1 被动轮询技术掩码 */
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_B;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
    wPasPollConfig |= (PHAC_DISCLOOP_POS_BIT_MASK_F212 | PHAC_DISCLOOP_POS_BIT_MASK_F424);
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_V;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
    wPasPollConfig |= PHAC_DISCLOOP_POS_BIT_MASK_18000P3M3;
#endif

/* 1.2 主动轮询技术掩码 */
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE
    wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_106;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE
    wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE
    wActPollConfig |= PHAC_DISCLOOP_ACT_POS_BIT_MASK_424;
#endif

/* 1.3 被动监听模式支持 */
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE
    wPasLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif

/* 1.4 主动监听模式支持 */
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE
    wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_A;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE
    wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F212;
#endif
#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE
    wActLisConfig |= PHAC_DISCLOOP_POS_BIT_MASK_F424;
#endif

/* 2. 根据配置 Profile 加载对应参数 */
    if(bProfile == PHAC_DISCLOOP_PROFILE_NFC)
    {
        /* passive Bailout bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, 0x00);
        CHECK_STATUS(status);

        /* Set Passive poll bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, wPasPollConfig);
        CHECK_STATUS(status);

        /* Set Active poll bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG, wActPollConfig);
        CHECK_STATUS(status);

        /* Set Passive listen bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, wPasLisConfig);
        CHECK_STATUS(status);

        /* Set Active listen bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, wActLisConfig);
        CHECK_STATUS(status);

        /* reset collision Pending */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_COLLISION_PENDING, PH_OFF);
        CHECK_STATUS(status);

        /* whether anti-collision is supported or not. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ANTI_COLL, PH_ON);
        CHECK_STATUS(status);

        /* Poll Mode default state*/
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
        CHECK_STATUS(status);

#ifdef  NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
        /* Device limit for Type A */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        /* Passive polling Tx Guard times in micro seconds. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTA_VALUE_US, 5100);
        CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
        /* Device limit for Type B */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTB_VALUE_US, 5100);
        CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
        /* Device limit for Type F */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEF_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        /* Guard time for Type F. This guard time is applied when Type F poll before Type B */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTFB_VALUE_US, 20400);
        CHECK_STATUS(status);

        /* Guard time for Type F. This guard time is applied when Type B poll before Type F */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTBF_VALUE_US, 15300);
        CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
        /* Device limit for Type V (ISO 15693) */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEV_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTV_VALUE_US, 5200);
        CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
        /* Device limit for 18000P3M3 */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_18000P3M3_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GT18000P3M3_VALUE_US, 10000);
        CHECK_STATUS(status);
#endif

        /* Discovery loop Operation mode */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_NFC);
        CHECK_STATUS(status);
    }
    /* 对于EMVCo模式, 专用于支付终端POS, 配置更加严格, 通常只允许Type A/B协议, 不使用P2P、不启动主动监听 */
    else if(bProfile == PHAC_DISCLOOP_PROFILE_EMVCO)
    {
        /* EMVCO */
        /* passive Bailout bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_BAIL_OUT, 0x00);
        CHECK_STATUS(status);

        /* passive poll bitmap config.只启用TypeA/B */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_POLL_TECH_CFG, (PHAC_DISCLOOP_POS_BIT_MASK_A | PHAC_DISCLOOP_POS_BIT_MASK_B));
        CHECK_STATUS(status);

        /* Active Listen bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_PAS_LIS_TECH_CFG, 0x00);
        CHECK_STATUS(status);

        /* Active Listen bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_LIS_TECH_CFG, 0x00);
        CHECK_STATUS(status);

        /* Active Poll bitmap config. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ACT_POLL_TECH_CFG, 0x00);
        CHECK_STATUS(status);

        /* Bool to enable LPCD feature. 禁用低功耗卡检测 */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ENABLE_LPCD, PH_OFF);
        CHECK_STATUS(status);

        /* reset collision Pending */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_COLLISION_PENDING, PH_OFF);
        CHECK_STATUS(status);

        /* whether anti-collision is supported or not.启用防冲突 */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_ANTI_COLL, PH_ON);
        CHECK_STATUS(status);

        /* Poll Mode default state*/
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
        CHECK_STATUS(status);

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS
        /* Device limit for Type A */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        /* Passive polling Tx Guard times in micro seconds. */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTA_VALUE_US, 5100);
        CHECK_STATUS(status);

        /* Configure FSDI for the 14443P4A tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_FSDI, 0x08);
        CHECK_STATUS(status);

        /* Configure CID for the 14443P4A tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_CID, 0x00);
        CHECK_STATUS(status);

        /* Configure DRI for the 14443P4A tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DRI, 0x00);
        CHECK_STATUS(status);

        /* Configure DSI for the 14443P4A tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEA_I3P4_DSI, 0x00);
        CHECK_STATUS(status);
#endif

#ifdef NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS
        /* Device limit for Type B */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DEVICE_LIMIT, 1);
        CHECK_STATUS(status);

        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_GTB_VALUE_US, 5100);
        CHECK_STATUS(status);

        /* Configure AFI for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_AFI_REQ, 0x00);
        CHECK_STATUS(status);

        /* Configure FSDI for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_FSDI, 0x08);
        CHECK_STATUS(status);

        /* Configure CID for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_CID, 0x00);
        CHECK_STATUS(status);

        /* Configure DRI for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DRI, 0x00);
        CHECK_STATUS(status);

        /* Configure DSI for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_DSI, 0x00);
        CHECK_STATUS(status);

        /* Configure Extended ATQB support for the type B tags */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TYPEB_EXTATQB, 0x00);
        CHECK_STATUS(status);
#endif
        /* Configure reader library mode */
        status = phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_OPE_MODE, RD_LIB_MODE_EMVCO);
        CHECK_STATUS(status);
    }
    else
    {
        /* Do Nothing */
    }
    return status;
}
#endif /* ENABLE_DISC_CONFIG */


/* 测试射频场 */
void TestRFField(void)
{
    phStatus_t status;
    uint32_t regValue;

    printf("\n=== RF FIELD TEST ===\n");

    // 2. 检查RF状态
    status = phhalHw_Pn5180_Instr_ReadRegister(pHal, RF_STATUS, &regValue);
    printf("RF_STATUS: 0x%08lX (status: 0x%04X)\n", regValue, status);

    // 3. 强制开启RF场
    printf("Turning RF Field ON...\n");
    status = phhalHw_FieldOn(pHal);
    printf("FieldOn status: 0x%04X\n", status);

    HAL_Delay(100);  // 等待RF场稳定

    // 4. 再次检查RF状态
    status = phhalHw_Pn5180_Instr_ReadRegister(pHal, RF_STATUS, &regValue);
    printf("RF_STATUS after FieldOn: 0x%08lX\n", regValue);

    // 5. 检查IRQ状态
    status = phhalHw_Pn5180_Instr_ReadRegister(pHal, IRQ_STATUS, &regValue);
    printf("IRQ_STATUS: 0x%08lX\n", regValue);

    printf("=== RF FIELD TEST COMPLETE ===\n\n");
}

/**
 * 检查是否为EMV兼容卡片
 */
uint8_t EMV_IsEMVCompatibleCard(void *pDataParams)
{
    phacDiscLoop_Sw_DataParams_t *pDiscLoop = (phacDiscLoop_Sw_DataParams_t *)pDataParams;

    // 检查检测到的技术类型
    uint16_t wTechDetected = 0;
    phStatus_t status = phacDiscLoop_GetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_TECH_DETECTED, &wTechDetected);

    if (status != PH_ERR_SUCCESS) {
        return 0;
    }

    // 检查是否为Type A卡片
    if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_A)) {
        // 检查是否支持ISO14443-4 (Type 4A)
        uint8_t sak = pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aSak;

        // SAK bit 5 = 1 表示支持ISO14443-4协议 (EMV所需)
        if ((sak & 0x20) != 0) {
        	DEBUG_PRINTF("Type A ISO14443-4 compatible card detected (SAK: 0x%02X)\r\n", sak);
            return 1;
        }
    }

    // 检查是否为Type B卡片 (也可能是EMV)
    if (PHAC_DISCLOOP_CHECK_ANDMASK(wTechDetected, PHAC_DISCLOOP_POS_BIT_MASK_B)) {
        DEBUG_PRINTF("Type B card detected\r\n");
        return 1; // Type B默认支持ISO14443-4
    }

    return 0;
}

/**
 * Select PPSE
 */
EMV_Result_t EMV_SelectPPSE(void)
{
    // Use your existing PPSE command
    uint8_t PPSE_SELECT_APDU[] = {
        0x00, 0xA4, 0x04, 0x00, 0x0E,
        0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
        0x00
    };

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    // Use ISO14443-4 protocol to exchange APDU
    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        PPSE_SELECT_APDU,
        sizeof(PPSE_SELECT_APDU),
        &ppRxBuffer,
        &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        // Check status word (SW1 SW2)
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        DEBUG_PRINTF("PPSE Response Status: %02X %02X, Length: %d\r\n", sw1, sw2, wRxLen);

        if (sw1 == 0x90 && sw2 == 0x00) {
            // Print response data (for debugging)
            DEBUG_PRINTF("PPSE Response Data: ");
            for (int i = 0; i < wRxLen-2 && i < 50; i++) { // Limit print length
                printf("%02X ", ppRxBuffer[i]);
            }
            printf("\r\n");

            return EMV_SUCCESS;
        } else if (sw1 == 0x6A && sw2 == 0x82) {
            DEBUG_PRINTF("PPSE Not Found (6A82)\r\n");
        }
    } else {
        DEBUG_PRINTF("PPSE Communication Failed, Status: 0x%04X\r\n", status);
    }

    return EMV_ERROR_PPSE_SELECT;
}

/**
 * Select Application
 */
EMV_Result_t EMV_SelectApplication(uint8_t *aid, uint8_t aid_len)
{
    uint8_t select_apdu[256];
    uint8_t apdu_len = 0;

    // Build SELECT APPLICATION APDU
    select_apdu[apdu_len++] = 0x00;  // CLA
    select_apdu[apdu_len++] = 0xA4;  // INS (SELECT)
    select_apdu[apdu_len++] = 0x04;  // P1 (Select by DF name)
    select_apdu[apdu_len++] = 0x00;  // P2
    select_apdu[apdu_len++] = aid_len; // LC

    memcpy(&select_apdu[apdu_len], aid, aid_len);
    apdu_len += aid_len;

    select_apdu[apdu_len++] = 0x00;  // LE

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        select_apdu,
        apdu_len,
        &ppRxBuffer,
        &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        DEBUG_PRINTF("Application Selection Response: %02X %02X\r\n", sw1, sw2);

        if (sw1 == 0x90 && sw2 == 0x00) {
            return EMV_SUCCESS;
        }
    }

    return EMV_ERROR_APP_SELECT;
}

/**
 * Get Processing Options
 */
EMV_Result_t EMV_GetProcessingOptions(uint32_t amount, uint16_t currency_code)
{
    uint8_t gpo_apdu[256];
    uint8_t apdu_len = 0;

    // Build GPO APDU (simplified version)
    gpo_apdu[apdu_len++] = 0x80;  // CLA
    gpo_apdu[apdu_len++] = 0xA8;  // INS (GET PROCESSING OPTIONS)
    gpo_apdu[apdu_len++] = 0x00;  // P1
    gpo_apdu[apdu_len++] = 0x00;  // P2
    gpo_apdu[apdu_len++] = 0x02;  // LC (simplified version, only send basic data)

    // Simple PDOL data
    gpo_apdu[apdu_len++] = 0x83;  // Tag
    gpo_apdu[apdu_len++] = 0x00;  // Length (empty data)

    gpo_apdu[apdu_len++] = 0x00;  // LE

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        gpo_apdu,
        apdu_len,
        &ppRxBuffer,
        &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        DEBUG_PRINTF("GPO Response: %02X %02X\r\n", sw1, sw2);

        if (sw1 == 0x90 && sw2 == 0x00) {
            return EMV_SUCCESS;
        }
    }

    return EMV_ERROR_GPO;
}

/**
 * Read Application Data
 */
EMV_Result_t EMV_ReadApplicationData(void)
{
    // Try to read several common records
    uint8_t records_to_read[][2] = {
        {0x01, 0x01}, // SFI 1, Record 1
        {0x02, 0x01}, // SFI 2, Record 1
        {0x01, 0x02}, // SFI 1, Record 2
    };

    int successful_reads = 0;

    for (int i = 0; i < sizeof(records_to_read) / sizeof(records_to_read[0]); i++) {
        uint8_t sfi = records_to_read[i][0];
        uint8_t record = records_to_read[i][1];

        if (EMV_ReadRecord(sfi, record) == EMV_SUCCESS) {
            successful_reads++;
        }
    }

    if (successful_reads > 0) {
        DEBUG_PRINTF("Successfully read %d records\r\n", successful_reads);
        return EMV_SUCCESS;
    }

    return EMV_ERROR_READ_RECORD;
}

/**
 * Read single record
 */
EMV_Result_t EMV_ReadRecord(uint8_t sfi, uint8_t record_num)
{
    uint8_t read_record_apdu[5];

    read_record_apdu[0] = 0x00;  // CLA
    read_record_apdu[1] = 0xB2;  // INS (READ RECORD)
    read_record_apdu[2] = record_num; // P1
    read_record_apdu[3] = (sfi << 3) | 0x04; // P2
    read_record_apdu[4] = 0x00;  // LE

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        read_record_apdu,
        sizeof(read_record_apdu),
        &ppRxBuffer,
        &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        if (sw1 == 0x90 && sw2 == 0x00) {
            DEBUG_PRINTF("SFI %d Record %d read successful, Length: %d\r\n", sfi, record_num, wRxLen-2);
            return EMV_SUCCESS;
        } else {
            DEBUG_PRINTF("SFI %d Record %d not found (%02X %02X)\r\n", sfi, record_num, sw1, sw2);
        }
    }

    return EMV_ERROR_READ_RECORD;
}

/**
 * Send data to Linux
 */
int EMV_SendDataToLinux(uint32_t amount, uint16_t currency_code)
{
    // Simplified version: Send transaction data to Linux via UART
    char tx_buffer[256];
    int len = snprintf(tx_buffer, sizeof(tx_buffer),
        "EMV_TRANSACTION:AMOUNT=%lu,CURRENCY=%04X\r\n",
        amount, currency_code);

    // Assume using UART1 to communicate with Linux
    extern UART_HandleTypeDef huart1;
    HAL_StatusTypeDef uart_status = HAL_UART_Transmit(&huart1, (uint8_t*)tx_buffer, len, 1000);

    if (uart_status == HAL_OK) {
        DEBUG_PRINTF("Sent to Linux: %s", tx_buffer);
        return 0;
    } else {
        DEBUG_PRINTF("UART transmission failed\r\n");
        return -1;
    }
}

/**
 * Wait for card removal
 */
void EMV_WaitForCardRemoval(void *pDataParams)
{
    phacDiscLoop_Sw_DataParams_t *pDiscLoop = (phacDiscLoop_Sw_DataParams_t *)pDataParams;

    DEBUG_PRINTF("Please remove the card...\r\n");

    // Set to card removal detection mode
    phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_REMOVAL);

    // Run removal detection
    phStatus_t status;
    int removal_attempts = 0;
    do {
        status = phacDiscLoop_Run(pDiscLoop, PHAC_DISCLOOP_ENTRY_POINT_POLL);
        HAL_Delay(100);
        removal_attempts++;

        // Avoid infinite waiting
        if (removal_attempts > 100) { // 10 seconds timeout
            DEBUG_PRINTF("Card removal detection timeout\r\n");
            break;
        }
    } while ((status & PH_ERR_MASK) != PHAC_DISCLOOP_NO_TECH_DETECTED);

    DEBUG_PRINTF("Card removed\r\n");

    // Reset to detection mode, prepare for next polling
    phacDiscLoop_SetConfig(pDiscLoop, PHAC_DISCLOOP_CONFIG_NEXT_POLL_STATE, PHAC_DISCLOOP_POLL_STATE_DETECTION);
}

// ==================================================
// 新增功能1: 收集卡片基础信息
// ==================================================
EMV_Result_t EMV_CollectCardBasicInfo(phacDiscLoop_Sw_DataParams_t *pDiscLoop, EMV_Complete_Card_Data_t *card_data)
{
    // 收集UID
    if (pDiscLoop->sTypeATargetInfo.bTotalTagsFound > 0) {
        card_data->card_uid_len = pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].bUidSize;
        memcpy(card_data->card_uid,
               pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aUid,
               card_data->card_uid_len);

        card_data->card_sak = pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aSak;
        memcpy(card_data->card_atqa,
               pDiscLoop->sTypeATargetInfo.aTypeA_I3P3[0].aAtqa,
               2);

        DEBUG_PRINTF("Card UID: ");
        for (int i = 0; i < card_data->card_uid_len; i++) {
            printf("%02X ", card_data->card_uid[i]);
        }
        printf("\r\n");
        DEBUG_PRINTF("SAK: 0x%02X, ATQA: %02X %02X\r\n",
                     card_data->card_sak, card_data->card_atqa[0], card_data->card_atqa[1]);

        return EMV_SUCCESS;
    }

    return EMV_ERROR_CARD_NOT_EMV;
}

// ==================================================
// 新增功能2: 收集PPSE信息
// ==================================================
EMV_Result_t EMV_CollectPPSEInfo(EMV_Complete_Card_Data_t *card_data)
{
    uint8_t PPSE_SELECT_APDU[] = {
        0x00, 0xA4, 0x04, 0x00, 0x0E,
        0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,
        0x00
    };

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        PPSE_SELECT_APDU,
        sizeof(PPSE_SELECT_APDU),
        &ppRxBuffer,
        &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        if (sw1 == 0x90 && sw2 == 0x00) {
            // 保存完整PPSE响应数据
            card_data->ppse_len = wRxLen;
            memcpy(card_data->ppse_data, ppRxBuffer, wRxLen);

            DEBUG_PRINTF("PPSE collected: %d bytes\r\n", wRxLen);
            return EMV_SUCCESS;
        }
    }

    // PPSE失败不是致命错误，可能是老卡
    DEBUG_PRINTF("PPSE not available, continuing...\r\n");
    card_data->ppse_len = 0;
    return EMV_SUCCESS;
}

// ==================================================
// 新增功能3: 收集应用选择信息
// ==================================================
EMV_Result_t EMV_CollectApplicationInfo(EMV_Complete_Card_Data_t *card_data)
{
    // 尝试多个常见AID
    uint8_t aids[][16] = {
        {0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10}, // MasterCard (7字节)
        {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}, // Visa (7字节)
        {0xA0, 0x00, 0x00, 0x03, 0x33, 0x01, 0x01}, // UnionPay (7字节)
    };
    uint8_t aid_lens[] = {7, 7, 7};
    const char* aid_names[] = {"MasterCard", "Visa", "UnionPay"};

    for (int i = 0; i < 3; i++) {
        DEBUG_PRINTF("Trying %s AID...\r\n", aid_names[i]);

        uint8_t select_apdu[32];
        uint8_t apdu_len = 0;

        select_apdu[apdu_len++] = 0x00;  // CLA
        select_apdu[apdu_len++] = 0xA4;  // INS
        select_apdu[apdu_len++] = 0x04;  // P1
        select_apdu[apdu_len++] = 0x00;  // P2
        select_apdu[apdu_len++] = aid_lens[i]; // LC

        memcpy(&select_apdu[apdu_len], aids[i], aid_lens[i]);
        apdu_len += aid_lens[i];
        select_apdu[apdu_len++] = 0x00;  // LE

        phStatus_t status;
        uint8_t *ppRxBuffer;
        uint16_t wRxLen = 0;

        status = phpalI14443p4_Exchange(
            phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
            PH_EXCHANGE_DEFAULT,
            select_apdu, apdu_len,
            &ppRxBuffer, &wRxLen
        );

        if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
            uint8_t sw1 = ppRxBuffer[wRxLen-2];
            uint8_t sw2 = ppRxBuffer[wRxLen-1];

            if (sw1 == 0x90 && sw2 == 0x00) {
                // 成功选择应用，保存响应数据
                card_data->app_select_len = wRxLen;
                memcpy(card_data->app_select_data, ppRxBuffer, wRxLen);

                DEBUG_PRINTF("%s application selected: %d bytes\r\n", aid_names[i], wRxLen);
                return EMV_SUCCESS;
            }
        }
    }

    return EMV_ERROR_APP_SELECT;
}

// ==================================================
// 新增功能4: 收集GPO信息
// ==================================================
EMV_Result_t EMV_CollectGPOInfo(EMV_Complete_Card_Data_t *card_data)
{
    uint8_t gpo_apdu[] = {
        0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00
    };

    phStatus_t status;
    uint8_t *ppRxBuffer;
    uint16_t wRxLen = 0;

    status = phpalI14443p4_Exchange(
        phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
        PH_EXCHANGE_DEFAULT,
        gpo_apdu, sizeof(gpo_apdu),
        &ppRxBuffer, &wRxLen
    );

    if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
        uint8_t sw1 = ppRxBuffer[wRxLen-2];
        uint8_t sw2 = ppRxBuffer[wRxLen-1];

        if (sw1 == 0x90 && sw2 == 0x00) {
            card_data->gpo_len = wRxLen;
            memcpy(card_data->gpo_data, ppRxBuffer, wRxLen);

            DEBUG_PRINTF("GPO collected: %d bytes\r\n", wRxLen);
            return EMV_SUCCESS;
        }
    }

    return EMV_ERROR_GPO;
}

// ==================================================
// 新增功能5: 收集所有记录
// ==================================================
EMV_Result_t EMV_CollectAllRecords(EMV_Complete_Card_Data_t *card_data)
{
    // 尝试读取常见的SFI记录
    uint8_t sfi_list[] = {1, 2, 3, 4};
    uint8_t max_records_per_sfi = 5;

    card_data->sfi_record_count = 0;

    for (int sfi_idx = 0; sfi_idx < sizeof(sfi_list); sfi_idx++) {
        uint8_t sfi = sfi_list[sfi_idx];

        for (uint8_t record = 1; record <= max_records_per_sfi; record++) {
            uint8_t read_record_apdu[5] = {
                0x00, 0xB2, record, (sfi << 3) | 0x04, 0x00
            };

            phStatus_t status;
            uint8_t *ppRxBuffer;
            uint16_t wRxLen = 0;

            status = phpalI14443p4_Exchange(
                phNfcLib_GetDataParams(PH_COMP_PAL_ISO14443P4),
                PH_EXCHANGE_DEFAULT,
                read_record_apdu, sizeof(read_record_apdu),
                &ppRxBuffer, &wRxLen
            );

            if (status == PH_ERR_SUCCESS && wRxLen >= 2) {
                uint8_t sw1 = ppRxBuffer[wRxLen-2];
                uint8_t sw2 = ppRxBuffer[wRxLen-1];

                if (sw1 == 0x90 && sw2 == 0x00) {
                    // 成功读取记录
                    if (card_data->sfi_record_count < 10) {
                        card_data->sfi_record_lens[card_data->sfi_record_count] = wRxLen;
                        memcpy(card_data->sfi_records[card_data->sfi_record_count],
                               ppRxBuffer, wRxLen);
                        card_data->sfi_record_count++;

                        DEBUG_PRINTF("SFI %d Record %d: %d bytes\r\n", sfi, record, wRxLen-2);
                    }
                } else {
                    // 记录不存在，尝试下一个
                    break;
                }
            }
        }
    }

    if (card_data->sfi_record_count > 0) {
        DEBUG_PRINTF("Total records collected: %d\r\n", card_data->sfi_record_count);
        return EMV_SUCCESS;
    }

    return EMV_ERROR_READ_RECORD;
}

// ==================================================
// 新增功能6: 发送完整数据到Linux
// ==================================================
EMV_Result_t EMV_SendCompleteDataToLinux(EMV_Complete_Card_Data_t *card_data)
{
    extern UART_HandleTypeDef huart1;
    char buffer[2048];
    int pos = 0;

    // 构建结构化数据包
    pos += sprintf(buffer + pos, "EMV_COMPLETE_DATA_START\r\n");

    // 基础卡片信息
    pos += sprintf(buffer + pos, "CARD_UID:");
    for (int i = 0; i < card_data->card_uid_len; i++) {
        pos += sprintf(buffer + pos, "%02X", card_data->card_uid[i]);
    }
    pos += sprintf(buffer + pos, "\r\n");

    pos += sprintf(buffer + pos, "CARD_SAK:%02X\r\n", card_data->card_sak);
    pos += sprintf(buffer + pos, "CARD_ATQA:%02X%02X\r\n",
                   card_data->card_atqa[0], card_data->card_atqa[1]);

    // 交易参数
    pos += sprintf(buffer + pos, "AMOUNT:%lu\r\n", card_data->amount);
    pos += sprintf(buffer + pos, "CURRENCY:%04X\r\n", card_data->currency_code);

    // PPSE数据
    if (card_data->ppse_len > 0) {
        pos += sprintf(buffer + pos, "PPSE_DATA:");
        for (int i = 0; i < card_data->ppse_len; i++) {
            pos += sprintf(buffer + pos, "%02X", card_data->ppse_data[i]);
        }
        pos += sprintf(buffer + pos, "\r\n");
    }

    // 应用选择数据
    if (card_data->app_select_len > 0) {
        pos += sprintf(buffer + pos, "APP_SELECT_DATA:");
        for (int i = 0; i < card_data->app_select_len; i++) {
            pos += sprintf(buffer + pos, "%02X", card_data->app_select_data[i]);
        }
        pos += sprintf(buffer + pos, "\r\n");
    }

    // GPO数据
    if (card_data->gpo_len > 0) {
        pos += sprintf(buffer + pos, "GPO_DATA:");
        for (int i = 0; i < card_data->gpo_len; i++) {
            pos += sprintf(buffer + pos, "%02X", card_data->gpo_data[i]);
        }
        pos += sprintf(buffer + pos, "\r\n");
    }

    // 记录数据
    pos += sprintf(buffer + pos, "RECORD_COUNT:%d\r\n", card_data->sfi_record_count);
    for (int i = 0; i < card_data->sfi_record_count; i++) {
        pos += sprintf(buffer + pos, "RECORD_%d:", i);
        for (int j = 0; j < card_data->sfi_record_lens[i]; j++) {
            pos += sprintf(buffer + pos, "%02X", card_data->sfi_records[i][j]);
        }
        pos += sprintf(buffer + pos, "\r\n");
    }

    pos += sprintf(buffer + pos, "EMV_COMPLETE_DATA_END\r\n");

    // 发送数据
    if (HAL_UART_Transmit(&huart1, (uint8_t*)buffer, pos, 5000) == HAL_OK) {
        DEBUG_PRINTF("Complete data sent to Linux: %d bytes\r\n", pos);
        return EMV_SUCCESS;
    }

    return EMV_ERROR_COMMUNICATION;
}

// ==================================================
// 新增功能7: 等待Linux处理结果
// ==================================================
EMV_Result_t EMV_WaitForLinuxResult(EMV_Complete_Card_Data_t *card_data)
{
    extern UART_HandleTypeDef huart1;
    uint8_t rx_buffer[256];
    uint32_t timeout = 10000; // 10秒超时

    DEBUG_PRINTF("Waiting for Linux processing result...\r\n");

    if (HAL_UART_Receive(&huart1, rx_buffer, sizeof(rx_buffer), timeout) == HAL_OK) {
        // 解析Linux响应
        if (strstr((char*)rx_buffer, "TRANSACTION_APPROVED") != NULL) {
            DEBUG_PRINTF("Transaction APPROVED by Linux\r\n");
            return EMV_SUCCESS;
        } else if (strstr((char*)rx_buffer, "TRANSACTION_DECLINED") != NULL) {
            DEBUG_PRINTF("Transaction DECLINED by Linux\r\n");
            return EMV_ERROR_TRANSACTION_DECLINED;
        } else {
            DEBUG_PRINTF("Linux response: %s\r\n", rx_buffer);
            return EMV_ERROR_COMMUNICATION;
        }
    }

    DEBUG_PRINTF("Timeout waiting for Linux response\r\n");
    return EMV_ERROR_COMMUNICATION;
}

// ==================================================
// 新增功能8: 硬件指示
// ==================================================
void EMV_ShowSuccessIndication(void)
{
    DEBUG_PRINTF("Transaction Successful!\r\n");
    // 可以添加LED闪烁、蜂鸣器提示等
    // beep_start(2, 200);  // 成功提示音
}

void EMV_ShowFailureIndication(void)
{
    DEBUG_PRINTF("Transaction Failed!\r\n");
    // 可以添加LED闪烁、蜂鸣器提示等
    // beep_start(3, 100);  // 失败提示音
}

