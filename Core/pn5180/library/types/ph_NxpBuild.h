/*----------------------------------------------------------------------------*/
/* Copyright 2009-2025 NXP                                                    */
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
 * Build System Definitions for Reader Library Framework.
 * $Author: NXP $
 * $Revision: $ (v07.13.00)
 * $Date: $
 *
 */

#ifndef PH_NXPBUILD_H
#define PH_NXPBUILD_H

#ifdef NXPBUILD_CUSTOMER_HEADER_INCLUDED
#   include "ph_NxpBuild_App.h"
#else /* NXPBUILD_CUSTOMER_HEADER_INCLUDED */
#   ifdef _WIN32
#       include <ph_NxpBuild_Pc.h>
#   else /* _WIN32 */
#      include <ph_NxpBuild_Platform.h>
#   endif /* _WIN32 */
#endif /* NXPBUILD_CUSTOMER_HEADER_INCLUDED */

/* #define  NXPRDLIB_REM_GEN_INTFS */

/** \defgroup ph_NxpBuild NXP Build
* \brief Controls build behaviour of components.
* @{
*/

/* NXPBUILD_DELETE: included code lines should be always removed from code */

/* NXP Build defines                            */
/* use #define to include components            */
/* comment out #define to exclude components    */

/* DEBUG build mode */

/*#define NXPBUILD__PH_DEBUG*/                      /**< DEBUG build definition */

#ifdef _DEBUG
#endif
/* HAL components */

#if defined (NXPBUILD__PHHAL_HW_RC663) || \
    defined (NXPBUILD__PHHAL_HW_PN7462AU) || \
    defined (NXPBUILD__PHHAL_HW_PN5180) || \
    defined (NXPBUILD__PHHAL_HW_PN5190) || \
    defined (NXPBUILD__PHHAL_HW_PN722X)
#define NXPBUILD__PHHAL_HW                  /**< Generic HAL definition */
#endif

#ifdef NXPBUILD__PHHAL_HW_RC663
    /* No active/target mode for RC663 */
    #undef NXPBUILD__PHHAL_HW_TARGET
    #undef NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE
    #undef NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE
    #undef NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE
#endif /* NXPBUILD__PHHAL_HW_RC663 */

/* PAL ISO 14443-3A components */

#if defined (NXPBUILD__PHPAL_I14443P3A_SW)
    #define NXPBUILD__PHPAL_I14443P3A           /**< Generic PAL ISO 14443-3A definition */
#endif

/* PAL ISO 14443-3B components */

#if defined (NXPBUILD__PHPAL_I14443P3B_SW)
    #define NXPBUILD__PHPAL_I14443P3B           /**< Generic PAL ISO 14443-3B definition */
#endif
/* PAL ISO 14443-4A components */

#if defined (NXPBUILD__PHPAL_I14443P4A_SW)
    #define NXPBUILD__PHPAL_I14443P4A           /**< Generic PAL ISO 14443-4A definition */
#endif

/* PAL ISO 14443-4 components */

#if defined (NXPBUILD__PHPAL_I14443P4_SW)
    #define NXPBUILD__PHPAL_I14443P4            /**< Generic PAL ISO 14443-4 definition */
#endif

/* PAL ISO 18092 Target component */

#if defined (NXPBUILD__PHPAL_I14443P4MC_SW)
    #define NXPBUILD__PHPAL_I14443P4MC          /**< Generic PAL ISO 18092 target definition */
#endif

/* PAL MIFARE product components */

#if defined (NXPBUILD__PHPAL_MIFARE_SW)
    #define NXPBUILD__PHPAL_MIFARE              /**< Generic PAL MIFARE product definition */
#endif

/* PAL ISO15693 ICode SLI components */

#if defined (NXPBUILD__PHPAL_SLI15693_SW)
    #define NXPBUILD__PHPAL_SLI15693            /**< Generic PAL Sli 15693 definition */
#endif

/* PAL FeliCa components */

/*#define HANDLE_MULTIPLE_FELICA_CARD_RESP */   /**< Enable handling of multiple FeliCa card response */

#if defined (NXPBUILD__PHPAL_FELICA_SW)
    #define NXPBUILD__PHPAL_FELICA              /**< Generic PAL FeliCa definition */
#endif

/* PAL ICode EPC/UID components */

#if defined (NXPBUILD__PHPAL_EPCUID_SW)
    #define NXPBUILD__PHPAL_EPCUID              /**< Generic PAL ICode EPC/UID definition */
#endif

/* PAL I18000p3m3 components */

#if defined (NXPBUILD__PHPAL_I18000P3M3_SW)
    #define    NXPBUILD__PHPAL_I18000P3M3            /**< Generic PAL I18000p3m3 definition */
#endif

/* PAL ISO 18092 components */

#if defined (NXPBUILD__PHPAL_I18092MPI_SW)
    #define NXPBUILD__PHPAL_I18092MPI           /**< Generic PAL ISO 18092 definition */
#endif

/* PAL ISO 18092 Target component */

#if defined (NXPBUILD__PHPAL_I18092MT_SW)
    #define NXPBUILD__PHPAL_I18092MT             /**< Generic PAL ISO 18092 target definition */
#endif

/* AC dicover loop component */

#if defined (NXPBUILD__PHAC_DISCLOOP_SW)
    #define NXPBUILD__PHAC_DISCLOOP             /**< Generic dicovery loop component */
#endif

#if defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P3_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_JEWEL_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS)
    #define NXPBUILD__PHAC_DISCLOOP_TYPEA_TAGS  /**< Detect Passive TypeA Tags/Peers */
#endif

#if defined (NXPBUILD__PHAC_DISCLOOP_FELICA_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS)
   #define NXPBUILD__PHAC_DISCLOOP_TYPEF_TAGS
#endif

#if defined (NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P3B_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEB_BPRIME_TAGS)
    #define NXPBUILD__PHAC_DISCLOOP_TYPEB_TAGS          /**< Detect TypeB Tags */
#endif

#if defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE) || \
    defined (NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE)
    #define NXPBUILD__PHAC_DISCLOOP_TARGET      /**< Configure Target Mode */
#endif

/*#define NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE*/      /**< Detect type A Active P2P Peer */
/*#define NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE*/   /**< Detect type F212 Active P2P Peer */
/*#define NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE*/   /**< Detect type F424 Active P2P Peer */

/*#define NXPBUILD__PHAC_DISCLOOP_P2P_ACTIVE*/

/* AL FeliCa components */

#if defined (NXPBUILD__PHAL_FELICA_SW)
    #define NXPBUILD__PHAL_FELICA                  /**< Generic AL FeliCa definition */
#endif

/* AL MIFARE Classic contactless IC components */

#if defined (NXPBUILD__PHAL_MFC_SW)
    #define NXPBUILD__PHAL_MFC                     /**< Generic AL MIFARE Classic definition */
#endif

/* AL MIFARE Plus contactless IC components */

#if defined (NXPBUILD__PHAL_MFP_SW)
    #define NXPBUILD__PHAL_MFP                     /**< Generic AL MIFARE Plus definition */
#endif

/* AL MIFARE Plus EV1 contactless IC components */

#if defined (NXPBUILD__PHAL_MFPEVX_SW)
    #define NXPBUILD__PHAL_MFPEVX                  /**< Generic AL MIFARE Plus EVx contactless IC definition */
#endif

/* AL MIFARE DESFire contactless IC Components */

#if defined (NXPBUILD__PHAL_MFDF_SW)
    #define NXPBUILD__PHAL_MFDF                    /**< Generic AL MIFARE DESFire definition */
#endif

/* AL MIFARE DESFire EVx contactless IC Components */

#if defined (NXPBUILD__PHAL_MFDFEVX_SW)
    #define NXPBUILD__PHAL_MFDFEVX                 /**< Generic AL MIFARE Desfire EVx definition */
#endif

/* AL MIFARE DESFire Light contactless IC Components */

#if defined (NXPBUILD__PHAL_MFDFLIGHT_SW)
    #define NXPBUILD__PHAL_MFDFLIGHT               /**< Generic AL MIFARE DESFire Light contactless IC definition */
#endif

/* AL MIFARE PRIME Ntag42XDna contactless IC components */

#if defined (NXPBUILD__PHAL_MFNTAG42XDNA_SW)
    #define NXPBUILD__PHAL_MFNTAG42XDNA            /**< Generic AL MIFARE Prime Ntag42XDna contactless IC definition */
#endif

/* AL MIFARE Ultralight contactless IC components */

#if defined (NXPBUILD__PHAL_MFUL_SW)
    #define NXPBUILD__PHAL_MFUL                    /**< Generic AL MIFARE Ultralight definition */
#endif

/* AL MIFARE DUOX contactless IC components */

#if defined (NXPBUILD__PHAL_MFDUOX_SW)
    #define NXPBUILD__PHAL_MFDUOX                  /**< Generic AL MIFARE DUOX contactless IC definition */
#endif

/* AL NTAG X DNA contactless IC components */

/* AL T1T components */

#if defined (NXPBUILD__PHAL_T1T_SW)
    #define NXPBUILD__PHAL_T1T                     /**< Generic AL Type 1 Tag definition */
#endif

/* AL TOP components */

#if defined (NXPBUILD__PHAL_TOP_SW)
    #define NXPBUILD__PHAL_TOP                     /**< Generic AL Tag Operations */
#endif

/* CE T4AT Card Emulation components */

#if defined (NXPBUILD__PHCE_T4T_SW)
    #define NXPBUILD__PHCE_T4T                     /**< Generic HCE */
#endif

/* AL Virtual Card Architecture components */

#if defined (NXPBUILD__PHAL_VCA_SW)
    #define NXPBUILD__PHAL_VCA                     /**< Generic AL Virtual Card Architecture definition */
#endif

/* DL FPGA Box components */

/* DL Amplifier components */

/* DL Thermostream components */

/* DL Oscilloscope components */

/* DL Master Amplifier Oscilloscope components */

/* DL Stepper components */

#if defined (NXPBUILD__PHAL_ICODE_SW)
    #define NXPBUILD__PHAL_ICODE                   /**< Generic AL ICode definition */
#endif

/* AL ISO 18000P3M3 components */

#if defined (NXPBUILD__PHAL_I18000P3M3_SW)
    #define NXPBUILD__PHAL_I18000P3M3              /**< Generic AL I18000p3m3 definition */
#endif

/* AL P40 PrivateCommands components */

/* AL P40 PublicCommand components */

/* CID Manager components */

#if defined (NXPBUILD__PH_CIDMANAGER_SW)
    #define NXPBUILD__PH_CIDMANAGER                /**< Generic CID Manager definition */
#endif

/* Crypto Sym components */

#if defined (NXPBUILD__PH_CRYPTOSYM_SW) || \
    defined (NXPBUILD__PH_CRYPTOSYM_MBEDTLS)
    #define NXPBUILD__PH_CRYPTOSYM                 /**< Generic Crypto Sym definition */
#endif

/* Crypto ASym components */

#if defined (NXPBUILD__PH_CRYPTOASYM_MBEDTLS) || \
    defined (NXPBUILD__PH_CRYPTOASYM_ECC) || \
    defined (NXPBUILD__PH_CRYPTOASYM_HASH)
    #define NXPBUILD__PH_CRYPTOASYM                /**< Generic Crypto ASym definition */
#endif

/* CryptoRng components */

#if defined (NXPBUILD__PH_CRYPTORNG_SW) || \
    defined (NXPBUILD__PH_CRYPTORNG_MBEDTLS)
    #define NXPBUILD__PH_CRYPTORNG                 /**< Generic CryptoRng definition */
#endif

/* KeyStore components */

#if defined (NXPBUILD__PH_KEYSTORE_SW) || \
    defined (NXPBUILD__PH_KEYSTORE_RC663)
    #define NXPBUILD__PH_KEYSTORE                  /**< Generic KeyStore definition */
#endif

/* TMIUtils component */
#define NXPBUILD__PH_TMIUTILS

/* LN components */

#if defined (NXPBUILD__PHLN_LLCP_SW)
    #define NXPBUILD__PHLN_LLCP                    /**< Generic Link layer definition */
#endif

/* SNEP components */

#if defined (NXPBUILD__PHNP_SNEP_SW)
    #define NXPBUILD__PHNP_SNEP                    /**< Generic HAL definition */
#endif

#if defined(NXPBUILD__PHHAL_HW_RC663)  || \
    defined(NXPBUILD__PHHAL_HW_PN5180) || \
    defined(NXPBUILD__PHHAL_HW_PN5190) || \
    defined(NXPBUILD__PHHAL_HW_PN722X)
    #define PH_PLATFORM_HAS_ICFRONTEND             /**< Platform has IC Frontend */
#endif

/* Log component */

/*#define NXPBUILD__PH_LOG*/

/* Enable/disable Debugging */
/*#define NXPBUILD__PH_DEBUG*/

/** @}
* end of ph_NxpBuild
*/

#endif /* PH_NXPBUILD_H */
