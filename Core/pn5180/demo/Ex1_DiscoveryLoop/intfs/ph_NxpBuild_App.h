/*----------------------------------------------------------------------------*/
/* Copyright 2016-2023 NXP                                                    */
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
* Application specific selection of Reader Library Components - CLEAN MINIMAL CONFIG FOR DISCOVERY LOOP
*
* $Author$
* $Revision$ (v07.13.00)
* $Date$
*
*/

#ifndef PH_NXPBUILD_APP_H_INC
#define PH_NXPBUILD_APP_H_INC

/** \defgroup ph_NxpBuild NXP Build
* \brief Controls the Inclusion of required components, Inclusion SRC/DATA within components and the Build Dependencies between the components
* @{
*/

/* NXPBUILD_DELETE: included code lines should be always removed from code */

/* NXP BUILD DEFINES */
/* use #define to include components            */
/* comment out #define to exclude components    */

/* DEBUG build mode */
/*#define NXPBUILD__PH_DEBUG*/                              /**< DEBUG build definition */

//#define NXPRDLIB_REM_GEN_INTFS

/*********************************************************************************************************************************************************************************/

/* ===================================================================
 * HAL LAYER - 只包含PN5180硬件抽象层
 * =================================================================== */

/* 根据你的平台，只启用PN5180 */
#define NXPBUILD__PHHAL_HW_PN5180                           /**< NFC Controller PN5180 HAL */

/* 自动检测其他平台（保留原逻辑但通常用不到） */
#if defined(__PN74XXXX__) || defined (__PN73XXXX__)
    #define NXPBUILD__PHHAL_HW_PN7462AU                     /**< NFC Controller PN7462AU HAL */
#endif

#ifdef __PN76XX__
    #ifdef __PN7642__
        #define NXPBUILD__PHHAL_HW_PN7642                   /**< NFC Controller PN7642 HAL */
    #elif __PN7640__
        #define NXPBUILD__PHHAL_HW_PN7640                   /**< NFC Controller PN7640 HAL */
    #else
        #error " PN76 platform definition (__PN7642__ or __PN7640__) missing !!! "
    #endif

    #if defined(__PN7642__) || defined(__PN7640__)
        #define NXPBUILD__PHHAL_HW_PN76XX                   /**< NFC Controller PN76XX HAL */
    #endif
#endif /* __PN76XX__ */

/* 其他板卡定义（通常用不到，但保留兼容性） */
#if defined(PHDRIVER_LPC1769PN5190_BOARD) || defined(PHDRIVER_K82F_PNEV5190B_BOARD)
#   define NXPBUILD__PHHAL_HW_PN5190
#endif

#if defined(PHDRIVER_LPC1769RC663_BOARD) || defined(PHDRIVER_FRDM_K82FRC663_BOARD)
#   define NXPBUILD__PHHAL_HW_RC663
#endif

/* Target模式支持检测 */
#if defined(NXPBUILD__PHHAL_HW_PN5180) || \
    defined(NXPBUILD__PHHAL_HW_PN5190) || \
    defined(NXPBUILD__PHHAL_HW_PN76XX) || \
    defined(NXPBUILD__PHHAL_HW_PN7462AU)
    #define NXPBUILD__PHHAL_HW_TARGET                       /**< Target mode macros enabled */
#endif

/*********************************************************************************************************************************************************************************/

/* ===================================================================
 * PAL LAYER - 只包含Discovery Loop必需的PAL组件
 * =================================================================== */

/* 只启用基础的ISO14443协议支持 */
#define NXPBUILD__PHPAL_I14443P3A_SW                        /**< PAL ISO 14443-3A SW Component */
#define NXPBUILD__PHPAL_I14443P3B_SW                        /**< PAL ISO 14443-3B SW Component */
#define NXPBUILD__PHPAL_I14443P4A_SW                        /**< PAL ISO 14443-4A SW Component */
#define NXPBUILD__PHPAL_I14443P4_SW                         /**< PAL ISO 14443-4 SW Component */

/* EPC UID支持（仅RC663需要，但保留检测逻辑） */
#ifdef NXPBUILD__PHHAL_HW_RC663
    #define NXPBUILD__PHPAL_EPCUID_SW                       /**< PAL EPC UID SW Component */
#endif

/* 所有复杂组件都被禁用 - 避免编译错误 */
/*
 * 这些组件会导致编译错误，因此全部禁用：
 * - NXPBUILD__PHPAL_MIFARE_SW      (Mifare相关)
 * - NXPBUILD__PHPAL_FELICA_SW      (FeliCa相关)
 * - NXPBUILD__PHPAL_SLI15693_SW    (ISO15693相关)
 * - NXPBUILD__PHPAL_I18000P3M3_SW  (18000p3m3相关)
 * - NXPBUILD__PHPAL_I18092MPI_SW   (P2P相关)
 * - NXPBUILD__PHPAL_I14443P4MC_SW  (Card Mode相关)
 * - NXPBUILD__PHPAL_I18092MT_SW    (Target Mode相关)
 */

/*********************************************************************************************************************************************************************************/

/* ===================================================================
 * DISCOVERY LOOP - 只包含基础发现循环功能
 * =================================================================== */
#define NXPBUILD__PHAC_DISCLOOP_SW                          /**< Discovery Loop Activity SW Component */

#ifdef NXPBUILD__PHAC_DISCLOOP_SW

    /* 启用LPCD支持 */
    #if defined(NXPBUILD__PHHAL_HW_PN5180)
        #define NXPBUILD__PHAC_DISCLOOP_LPCD                /**< LPCD support for PN5180 */
    #endif

    /* 只启用Type A卡片检测 - 最简单的配置 */
    #ifdef NXPBUILD__PHPAL_I14443P3A_SW
        #define NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P3_TAGS     /**< Type A Layer 3 cards (MFC, MFUL等) */
        // #define NXPBUILD__PHAC_DISCLOOP_TYPEA_JEWEL_TAGS /**< T1T/Jewel cards - 暂时注释 */

        #if defined(NXPBUILD__PHPAL_I14443P4A_SW) && defined(NXPBUILD__PHPAL_I14443P4_SW)
            #define NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS /**< Type A Layer 4 cards (MFDF, T4AT等) */
        #endif
    #endif

    /* Type B卡片检测 */
    #ifdef NXPBUILD__PHPAL_I14443P3B_SW
        #define NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P3B_TAGS    /**< Type B Layer 3 cards */
        #ifdef NXPBUILD__PHPAL_I14443P4_SW
            #define NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS /**< Type B Layer 4 cards */
        #endif
    #endif

    /* 注释掉所有复杂的卡片类型，避免编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_FELICA_TAGS          /**< FeliCa cards - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS           /**< Type V cards - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS      /**< 18000p3m3 cards - 导致编译错误 */

    /* 注释掉所有P2P支持，避免编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS       /**< P2P support - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE     /**< Active P2P - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE  /**< F212 Active P2P - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE  /**< F424 Active P2P - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS       /**< F P2P - 导致编译错误 */

    /* 注释掉Target模式，避免编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE  /**< Target mode - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE   /**< Active Target - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE /**< F212 Target - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE  /**< F212 Active Target - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE /**< F424 Target - 导致编译错误 */
    // #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE  /**< F424 Active Target - 导致编译错误 */

#endif /* NXPBUILD__PHAC_DISCLOOP_SW */

/*********************************************************************************************************************************************************************************/

/* ===================================================================
 * NFCLIB - 简化API接口
 * =================================================================== */
#define NXPBUILD__PHNFCLIB                                  /**< Simplified API Interface */

/*********************************************************************************************************************************************************************************/

/* ===================================================================
 * 基础组件 - 只包含必需的
 * =================================================================== */
#define NXPBUILD__PH_KEYSTORE_SW                            /**< SW KeyStore Component */
#define NXPBUILD__PH_CRYPTOSYM_SW                           /**< Crypto Symbols SW Component */
#define NXPBUILD__PH_CRYPTORNG_SW                           /**< Crypto RNG SW Component */

/* 注释掉所有应用层组件，减少依赖 */
// #define NXPBUILD__PHAL_FELICA_SW                         /**< AL FeliCa SW Component - 导致编译错误 */
// #define NXPBUILD__PHAL_MFC_SW                            /**< AL MIFARE Classic - 导致编译错误 */
// #define NXPBUILD__PHAL_MFUL_SW                           /**< AL Mifare Ultralight - 导致编译错误 */
// #define NXPBUILD__PHAL_MFDF_SW                           /**< AL Mifare DesFire - 导致编译错误 */
// #define NXPBUILD__PHAL_T1T_SW                            /**< AL Type T1 Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_ICODE_SW                          /**< AL ICODE SW - 导致编译错误 */
// #define NXPBUILD__PHAL_I18000P3M3_SW                     /**< AL ISO18000p3m3 - 导致编译错误 */

/* 注释掉所有TOP层组件 */
// #define NXPBUILD__PHAL_TOP_T1T_SW                        /**< AL TOP T1T Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_T2T_SW                        /**< AL TOP T2T Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_T3T_SW                        /**< AL TOP T3T Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_T4T_SW                        /**< AL TOP T4T Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_T5T_SW                        /**< AL TOP T5T Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_MFC_SW                        /**< AL TOP MFC Tag - 导致编译错误 */
// #define NXPBUILD__PHAL_TOP_SW                            /**< AL for TagOps Mapping - 导致编译错误 */

/* 注释掉HCE和LLCP/SNEP组件 */
// #define NXPBUILD__PHCE_T4T_SW                            /**< AL HCE T2AT SW Component - 导致编译错误 */
// #define NXPBUILD__PHLN_LLCP_SW                           /**< Link LLCP SW Component - 导致编译错误 */
// #define NXPBUILD__PHNP_SNEP_SW                           /**< Protocol SNEP SW Component - 导致编译错误 */

/* Enable/disable Debugging */
/*#define NXPBUILD__PH_DEBUG*/                              /**< TODO: To be checked if required */

/** @}
* end of ph_NxpBuild
*/

#endif /* PH_NXPBUILD_APP_H_INC */
