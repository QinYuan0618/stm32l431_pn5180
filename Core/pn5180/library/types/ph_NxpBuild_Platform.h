/*----------------------------------------------------------------------------*/
/* Copyright 2015-2020, 2022-2025 NXP                                         */
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

#ifndef PH_NXPBUILD_PLATFORM_H
#define PH_NXPBUILD_PLATFORM_H

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

#define NXPRDLIB_REM_GEN_INTFS

/*********************************************************************************************************************************************************************************/

#if defined(__PN74XXXX__) || defined (__PN73XXXX__)
    #define NXPBUILD__PHHAL_HW_PN7462AU                     /**< NFC Controller PN7462AU HAL */
#endif

#ifdef __PN76XX__
    #ifdef __PN7642__
        #define NXPBUILD__PHHAL_HW_PN7642                   /**< NFC Controller PN7642 HAL */
        #ifndef NXPBUILD__PSP_SW_MODE_ENABLE
            #define NXPBUILD__PHHAL_HW_SAMAV3               /**< SAMAV3 HAL Component is included */

        #endif /* NXPBUILD__PSP_SW_MODE_ENABLE */
    #elif __PN7640__
        #define NXPBUILD__PHHAL_HW_PN7640                   /**< NFC Controller PN7640 HAL */
    #else
        #error " PN76 platform definition (__PN7642__ or __PN7640__) missing !!! "
    #endif

    #if defined(__PN7642__) || defined(__PN7640__)
        #define NXPBUILD__PHHAL_HW_PN76XX                   /**< NFC Controller PN76XX HAL */
    #endif
#endif /* __PN76XX__ */

#if defined(PHDRIVER_LPC1769PN5180_BOARD)    || \
    defined(PHDRIVER_FRDM_K82FPN5180_BOARD)
    #define NXPBUILD__PHHAL_HW_PN5180                       /**< NFC Reader PN5180 HAL */
#endif

#if defined(PHDRIVER_LPC1769RC663_BOARD)     || \
    defined(PHDRIVER_FRDM_K82FRC663_BOARD)
    #define NXPBUILD__PHHAL_HW_RC663                        /**< NFC Reader RC663 HAL */
//    #define NXPBUILD__PHHAL_HW_RC663_CUSTOM_DEBUG
#endif

#if defined(PHDRIVER_LPC1769PN5190_BOARD)    || \
    defined(PHDRIVER_LPC1769_MBDB_BOARD)     || \
    defined(PHDRIVER_K82F_PNEV5190B_BOARD)
    #define NXPBUILD__PHHAL_HW_PN5190                       /**< NFC Reader PN5190 HAL */
#endif

#if defined (PH_DRIVER_LPC55S16_PN7220_BOARD_I2C)  || \
    defined (PH_DRIVER_LPC55S16_PN7220_BOARD_SPI)  || \
	defined (PH_DRIVER_LPC55S16_PN77x_BOARD_I2C)   || \
    defined (PH_DRIVER_K82F_PN7220_BOARD_SPI)
    #define NXPBUILD__PHHAL_HW_PN722X                       /**< NFC Controller PN722X HAL */
#endif

#if defined(NXPBUILD__PHHAL_HW_RC663)   || \
    defined(NXPBUILD__PHHAL_HW_PN5180)  || \
    defined(NXPBUILD__PHHAL_HW_PN5190)  || \
    defined(NXPBUILD__PHHAL_HW_PN722X)
    #define PH_PLATFORM_HAS_ICFRONTEND                      /**< Platform has IC Frontend */
#endif

#if defined(NXPBUILD__PHHAL_HW_PN5180)  || \
    defined(NXPBUILD__PHHAL_HW_PN5190)  || \
    defined(NXPBUILD__PHHAL_HW_PN76XX)  || \
    defined(NXPBUILD__PHHAL_HW_PN7462AU)
    #define NXPBUILD__PHHAL_HW_TARGET                       /**< Dependency checking if target mode macros should be enabled */
#endif

/*********************************************************************************************************************************************************************************/

#define NXPBUILD__PHPAL_I14443P3A_SW                        /**< PAL ISO 14443-3A SW Component is included. */

#define NXPBUILD__PHPAL_I14443P3B_SW                        /**< PAL ISO 14443-3B SW Component is included. */

#define NXPBUILD__PHPAL_I14443P4A_SW                        /**< PAL ISO 14443-4A SW Component is included. */

#define NXPBUILD__PHPAL_I14443P4_SW                         /**< PAL ISO 14443-4 SW Component is included. */

#define NXPBUILD__PHPAL_MIFARE_SW                           /**< PAL MIFARE product SW Component is included */
/*#define NXPBUILD__PHPAL_MIFARE_STUB*/                     /**< PAL MIFARE product STUB Component is included */

#define NXPBUILD__PHPAL_FELICA_SW                           /**< PAL FeliCa SW Component is included. */

#define NXPBUILD__PHPAL_SLI15693_SW                         /**< PAL SLI 15693 Component is included. */

    #define NXPBUILD__PHPAL_I18000P3M3_SW                   /**< PAL ISO 18000p3m3 Component is included. */

#ifdef NXPBUILD__PHHAL_HW_RC663                             /**< If FE HAL is RC663, then include EPC UID PAL as required, otherwise exclude. */
    #define NXPBUILD__PHPAL_EPCUID_SW                       /**< PAL EPC UID SW Component is included. */
#endif /* NXPBUILD__PHHAL_HW_RC663 */

    #define NXPBUILD__PHPAL_I18092MPI_SW                    /**< PAL ISO18092 (P2P) SW Component is included. */

#ifdef NXPBUILD__PHPAL_I18092MPI_SW                         /**< If FE HAL is RC663, then include EPC UID PAL as required, otherwise exclude. */
    #define NXPBUILD__PHPAL_I18092MPI_SW_PROPRIETARY_PSL    /**< PAL ISO 18092 Initiator Mode proprietary PSL support. */
#endif /* NXPBUILD__PHPAL_I18092MPI_SW */

#ifndef NXPBUILD__PHHAL_HW_RC663                            /**< If FE HAL is RC663, then exclude ISO14443 Card Mode PAL & ISO18092 Target Mode PAL, otherwise include as required. */
        #define NXPBUILD__PHPAL_I14443P4MC_SW               /**< PAL ISO 14443-4 Card Mode SW Component is included. */

            #define NXPBUILD__PHPAL_I18092MT_SW             /**< PAL ISO 18092 Target Mode SW Component is included. */

        #ifdef NXPBUILD__PHPAL_I18092MT_SW                      /**< If FE HAL is RC663, then include EPC UID PAL as required, otherwise exclude. */
            #define NXPBUILD__PHPAL_I18092MT_SW_PROPRIETARY_PSL /**< PAL ISO 18092 Target Mode proprietary PSL support. */
        #endif /* NXPBUILD__PHPAL_I18092MT_SW */
#endif /* NXPBUILD__PHHAL_HW_RC663 */

/*********************************************************************************************************************************************************************************/

#define NXPBUILD__PHAC_DISCLOOP_SW                          /**< Discovery Loop Activity SW Component is included. */

#ifdef NXPBUILD__PHAC_DISCLOOP_SW                           /**< If DiscLoop SW Component is included,  macros( & it's dependencies) to include/exclude SRC/DATA within Discloop is defined. */

    #if defined (NXPBUILD__PHHAL_HW_PN5180)   || \
        defined (NXPBUILD__PHHAL_HW_PN5190)   || \
        defined (NXPBUILD__PHHAL_HW_RC663)    || \
        defined (NXPBUILD__PHHAL_HW_PN7462AU) || \
        defined (NXPBUILD__PHHAL_HW_PN7642)
        #define NXPBUILD__PHAC_DISCLOOP_LPCD                /**< SRC to enable LPCD is included. */
    #endif

    #ifdef  NXPBUILD__PHPAL_I14443P3A_SW
        #define NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P3_TAGS     /**< SRC/DATA to Detect/CollRes/Activate cards such as MFC, MFUL, MFP SL1 etc is included. */
        #define NXPBUILD__PHAC_DISCLOOP_TYPEA_JEWEL_TAGS    /**< SRC/DATA to Detect cards such as NFC Forum T1T, Topaz/Jewel is included. */

        #if defined(NXPBUILD__PHPAL_I14443P4A_SW) && \
            defined(NXPBUILD__PHPAL_I14443P4_SW)
            #define NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS /**< SRC/DATA to Detect cards such as MFDF, MFP, T4AT NFC Forum Tag or Type A EMVCo is included. */
        #endif
    #endif /* NXPBUILD__PHPAL_I14443P3A_SW */

    #if defined(NXPBUILD__PHPAL_I14443P3A_SW) && \
        defined(NXPBUILD__PHPAL_I18092MPI_SW)
        #define NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_TAGS      /**< SRC/DATA to Detect Peer Passive Type A P2P Target mode devices is included. */
    #endif

    #ifndef NXPBUILD__PHHAL_HW_RC663
        #ifdef NXPBUILD__PHPAL_I18092MPI_SW
            #define NXPBUILD__PHAC_DISCLOOP_TYPEA_P2P_ACTIVE       /**< SRC/DATA to Detect Peer Active Type A P2P Target mode devices is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_P2P_ACTIVE    /**< SRC/DATA to Detect Peer Active Type F212 P2P Target mode devices is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_P2P_ACTIVE    /**< SRC/DATA to Detect Peer Active Type F424 P2P Target mode devices is included. */
        #endif /* NXPBUILD__PHPAL_I18092MPI_SW */
    #endif /* NXPBUILD__PHHAL_HW_RC663 */

    #ifdef NXPBUILD__PHPAL_FELICA_SW
        #define NXPBUILD__PHAC_DISCLOOP_FELICA_TAGS                /**< SRC/DATA to Detect FeliCa Cards is included. */
        #ifdef  NXPBUILD__PHPAL_I18092MPI_SW
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF_P2P_TAGS         /**< SRC/DATA to Detect Peer Passive Type F P2P Target mode devices is included. */
        #endif /* NXPBUILD__PHPAL_I18092MPI_SW */
    #endif /* NXPBUILD__PHPAL_FELICA_SW */

    #ifdef NXPBUILD__PHPAL_I14443P3B_SW
        #define NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P3B_TAGS           /**< SRC/DATA to Detect Type B Cards that operate at Layer3 level is included */
        #ifdef NXPBUILD__PHPAL_I14443P4_SW
            #define NXPBUILD__PHAC_DISCLOOP_TYPEB_I3P4B_TAGS       /**< SRC/DATA to Detect Type B Cards such as NFC Forum Type 4 Tags, EMVCo Type B Cards etc is included */
        #endif /* NXPBUILD__PHPAL_I14443P4_SW */
    #endif /* NXPBUILD__PHPAL_I14443P3B_SW */

    #ifdef NXPBUILD__PHPAL_SLI15693_SW
        #define NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS                 /**< SRC/DATA to Detect Type V Cards such as ICODE SLI/SLIX/SLI2/Tesa Cards is included*/
    #endif /* NXPBUILD__PHPAL_SLI15693_SW */

    #ifdef NXPBUILD__PHPAL_I18000P3M3_SW
        #define NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS            /**< SRC/DATA to Detect ICODE ILT Cards such as  SMARTRAC StackIt Cards is included*/
    #endif /* NXPBUILD__PHPAL_I18000P3M3_SW */

    #ifndef NXPBUILD__PHHAL_HW_RC663                               /**< If FE HAL is RC663, target mode is not supported at all, hence exclude those SRC, otherwise include as required */
        #ifdef NXPBUILD__PHHAL_HW_TARGET
            #define NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_PASSIVE   /**< SRC to Initialize Type A passive listen config and subsequently call HAL AutoColl is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEA_TARGET_ACTIVE    /**< SRC to Initialize Type A active listen config and subsequently call HAL AutoColl is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_PASSIVE/**< SRC to Initialize Type F212 passive listen config and subsequently call HAL AutoColl is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF212_TARGET_ACTIVE /**< SRC to Initialize Type F212 active listen config and subsequently call HAL AutoColl is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_PASSIVE/**< SRC to Initialize Type F424 passive listen config and subsequently call HAL AutoColl is included. */
            #define NXPBUILD__PHAC_DISCLOOP_TYPEF424_TARGET_ACTIVE /**< SRC to Initialize Type F424 active listen config and subsequently call HAL AutoColl is included. */
        #endif /* NXPBUILD__PHHAL_HW_TARGET */
    #endif /* NXPBUILD__PHHAL_HW_RC663 */

#endif /* NXPBUILD__PHAC_DISCLOOP_SW */

/*********************************************************************************************************************************************************************************/

#define NXPBUILD__PHNFCLIB                                      /**< Simplified API Interface, If enabling this the entry point should be this component in the application */

#ifdef NXPBUILD__PHNFCLIB
    #define NXPBUILD__PHNFCLIB_PROFILES                         /**< Simplified API Interface to provide different profiles to user. */
    #ifdef NXPBUILD__PHNFCLIB_PROFILES
        #define NXPBUILD__PH_NFCLIB_ISO                         /**< Enable the ISO profile of Simplified API */
        #define NXPBUILD__PH_NFCLIB_EMVCO                       /**< Enable the EMVCO profile of Simplified API */
        /*#define NXPBUILD__PH_NFCLIB_NFC*/                     /**< Enable the NFC profile of Simplified API */
    #endif /* NXPBUILD__PHNFCLIB_PROFILES */
#endif /* NXPBUILD__PHNFCLIB */

#ifdef NXPBUILD__PH_NFCLIB_ISO

    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P3_TAGS
        #define NXPBUILD__PH_NFCLIB_ISO_MFC
        #define NXPBUILD__PH_NFCLIB_ISO_MFUL
    #endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P3_TAGS */

    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS
        #define NXPBUILD__PH_NFCLIB_ISO_MFDF
    #endif /* NXPBUILD__PHAC_DISCLOOP_TYPEA_I3P4_TAGS */

    #ifdef NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS
         #define NXPBUILD__PH_NFCLIB_ISO_15693
    #endif /* NXPBUILD__PHAC_DISCLOOP_TYPEV_TAGS*/

   #ifdef NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS
      #define NXPBUILD__PH_NFCLIB_ISO_18000
   #endif /* NXPBUILD__PHAC_DISCLOOP_I18000P3M3_TAGS */

#endif /* NXPBUILD__PH_NFCLIB_ISO*/

/*********************************************************************************************************************************************************************************/

/*#define NXPBUILD__PH_CIDMANAGER_SW*/                          /**< CID Manager SW Component is included. */

    #define NXPBUILD__PH_KEYSTORE_SW                            /**< SW KeyStore Component is included. */

#if defined(NXPBUILD__PHHAL_HW_RC663) && \
    !defined(NXPBUILD__PH_KEYSTORE_SW)
    #define NXPBUILD__PH_KEYSTORE_RC663                         /**< RC663 KeyStore Component is included. */
#endif

    #define NXPBUILD__PH_CRYPTOSYM_SW                          /**< Symmetric Crypto Symbols Software Component is included. */
    #ifndef NXPBUILD__PH_CRYPTOSYM_SW
        #define NXPBUILD__PH_CRYPTOSYM_MBEDTLS                 /**< Symmetric Crypto Symbols mBedTLS Component is included. */
    #endif /* NXPBUILD__PH_CRYPTOSYM_SW */

#ifdef NXPBUILD__PH_CRYPTOSYM_SW
    #define NXPBUILD__PH_CRYPTORNG_SW                           /**< Crypto RNG SW Component is included. */
#endif /* NXPBUILD__PH_CRYPTOSYM_SW */

#ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS
    #define NXPBUILD__PH_CRYPTORNG_MBEDTLS                      /**< Crypto RNG mBedTLS Component is included. */
#endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */

#define NXPBUILD__PH_TMIUTILS                                   /**< TMIUtils component */

#define NXPBUILD__PHAL_VCA_SW                                   /**< Software Virtual Card Architecture */

/*********************************************************************************************************************************************************************************/

#ifdef NXPBUILD__PHPAL_FELICA_SW
    #define NXPBUILD__PHAL_FELICA_SW                            /**< AL FeliCa SW Component is included */
#endif /* NXPBUILD__PHPAL_FELICA_SW */

#ifdef NXPBUILD__PHPAL_MIFARE_SW
    #if defined(NXPBUILD__PH_KEYSTORE_SW) || \
        defined(NXPBUILD__PH_KEYSTORE_RC663)
        #define NXPBUILD__PHAL_MFC_SW                           /**< AL MIFARE Classic contactless IC SW Component is included */
    #endif

    #define NXPBUILD__PHAL_MFUL_SW                              /**< AL MIFARE Ultralight contactless IC SW Component is included */

    #define NXPBUILD__PHAL_MFNTAG42XDNA_SW                      /**< AL MIFARE Prime Ntag42XDna contactless IC SW Component is included */

    #define NXPBUILD__PHAL_MFDFLIGHT_SW                         /**< AL MIFARE DESFire Light contactless IC SW Component is included */

    #define NXPBUILD__PHAL_MFDF_SW                              /**< AL MIFARE DESFire contactless IC SW Component is included */
    #ifdef NXPBUILD__PH_CRYPTOSYM_SW
        #define NXPBUILD__PH_NDA_MFDF                           /**< MIFARE DESFire implementation under NDA */
    #endif /* NXPBUILD__PH_CRYPTOSYM_SW */

    #if defined(NXPBUILD__PH_TMIUTILS) || \
        defined(NXPBUILD__PHAL_VCA_SW)

            #define NXPBUILD__PHAL_MFDFEVX_SW                   /**< AL MIFARE DESFire EVX contactless IC SW Component is included */

        /*#define RDR_LIB_PARAM_CHECK*/                         /**< AL MIFARE DESFire EVX parameter check compilation switch */
        #define NXPBUILD__PHAL_MFP_SW                           /**< AL MIFARE Plus contactless IC SW Component is included */

            #define NXPBUILD__PHAL_MFPEVX_SW                    /**< AL MIFARE Plus EVx contactless IC SW Component is included */

        /*#define NXPBUILD__PHAL_MFDUOX_SW*/                    /**< AL MIFARE DUOX contactless IC SW Component is included */
        /*#define NXPBUILD__PHAL_NTAGXDNA_SW*/                  /**< AL NTAG X DNA contactless IC SW Component is included */

        #if defined(NXPBUILD__PH_CRYPTOSYM_SW) || \
            defined(NXPBUILD__PH_CRYPTOSYM_MBEDTLS)
            #define NXPBUILD__PHAL_MFDFEVX_NDA                  /**< MIFARE DESFire EVx build macro for IP Protection */
            #define NXPBUILD__PH_NDA_MFP                        /**< MIFARE Plus implementation under NDA */
            #define NXPBUILD__PHAL_MFPEVX_NDA                   /**< MIFARE Plus EVx implementation under NDA */
            #ifdef NXPBUILD__PHAL_MFDUOX_SW
                #define NXPBUILD__PHAL_MFDUOX_NDA               /**< MIFARE DUOX implementation under NDA */
            #endif /* NXPBUILD__PHAL_MFDUOX_SW */
            #ifdef NXPBUILD__PHAL_NTAGXDNA_SW
                #define NXPBUILD__PHAL_NTAGXDNA_NDA             /**< NTAG X DNA implementation under NDA */
            #endif /* NXPBUILD__PHAL_NTAGXDNA_SW */
        #endif
    #endif
#endif /* NXPBUILD__PHPAL_MIFARE_SW */

#if defined(NXPBUILD__PHAL_MFDUOX_SW) || \
    defined(NXPBUILD__PHAL_NTAGXDNA_SW)
    /* Below dependency components enabled for MIFARE DUOX */
    #define NXPBUILD__PH_KEYSTORE_ASYM
    #define NXPBUILD__PH_CRYPTOASYM_MBEDTLS                    /**< Asymmetric Crypto Symbols mBedTLS Component is included. */
    #define NXPBUILD__PH_CRYPTOASYM_ECC                        /**< Crypto ASym mBedTLS Component for ECC is included.*/
    #define NXPBUILD__PH_CRYPTOASYM_HASH                       /**< Crypto ASym mBedTLS Component for HASH is included.*/
    /* Below Crypto components disabled for MIFARE DUOX */
    #undef NXPBUILD__PH_CRYPTOSYM_SW                           /**< Symmetric Crypto Symbols Software Component is excluded. */
    #undef NXPBUILD__PH_CRYPTORNG_SW                           /**< Crypto RNG SW Component is excluded. */
    /* Below Crypto components enabled for MIFARE DUOX */
    #ifndef NXPBUILD__PH_CRYPTOSYM_SW
        #define NXPBUILD__PH_CRYPTOSYM_MBEDTLS                 /**< Symmetric Crypto Symbols mBedTLS Component is included. */
    #endif /* NXPBUILD__PH_CRYPTOSYM_SW */
    #ifdef NXPBUILD__PH_CRYPTOSYM_MBEDTLS
        #define NXPBUILD__PH_CRYPTORNG_MBEDTLS                 /**< Crypto RNG mBedTLS Component is included. */
    #endif /* NXPBUILD__PH_CRYPTOSYM_MBEDTLS */
#endif /* NXPBUILD__PHAL_MFDUOX_SW */

#ifdef NXPBUILD__PHPAL_SLI15693_SW

    #define NXPBUILD__PHAL_ICODE_SW                             /**< ICode implementation is included */
    #define PHAL_ICODE_ENABLE_CHAINING                          /**< ICode Chaining is implemented */

#endif /* NXPBUILD__PHPAL_SLI15693_SW */

#define NXPBUILD__PHAL_T1T_SW                                   /**< AL T1 Tag SW Component is included */

#ifdef NXPBUILD__PHAL_T1T_SW
    #define NXPBUILD__PHAL_TOP_T1T_SW                           /**< AL TOP T1T Tag SW Component is included */
#endif /* NXPBUILD__PHAL_T1T_SW */
#ifdef NXPBUILD__PHAL_MFUL_SW
    #define NXPBUILD__PHAL_TOP_T2T_SW                           /**< AL TOP T2T Tag SW Component is included */
#endif /* NXPBUILD__PHAL_MFUL_SW */
#ifdef NXPBUILD__PHAL_FELICA_SW
    #define NXPBUILD__PHAL_TOP_T3T_SW                           /**< AL TOP T3T Tag SW Component is included */
#endif /* NXPBUILD__PHAL_FELICA_SW */
#ifdef NXPBUILD__PHPAL_MIFARE_SW
    #define NXPBUILD__PHAL_TOP_T4T_SW                           /**< AL TOP T4T Tag SW Component is included */
#endif /* NXPBUILD__PHPAL_MIFARE_SW */
#ifdef NXPBUILD__PHAL_ICODE_SW
    #define NXPBUILD__PHAL_TOP_T5T_SW                           /**< AL TOP T5T Tag SW Component is included */
#endif /* NXPBUILD__PHAL_ICODE_SW*/
#ifdef NXPBUILD__PHPAL_I14443P3A_SW
    #define NXPBUILD__PHAL_TOP_MFC_SW                           /**< AL TOP MFC Tag SW Component is included */
#endif /* NXPBUILD__PHPAL_I14443P3A_SW */

#if defined(NXPBUILD__PHAL_TOP_T1T_SW) || \
    defined(NXPBUILD__PHAL_TOP_T2T_SW) || \
    defined(NXPBUILD__PHAL_TOP_T3T_SW) || \
    defined(NXPBUILD__PHAL_TOP_T4T_SW) || \
    defined(NXPBUILD__PHAL_TOP_T5T_SW) || \
    defined(NXPBUILD__PHAL_TOP_MFC_SW)
    #define NXPBUILD__PHAL_TOP_SW                               /**< AL for TagOps Mapping SW Component is included.Required for NDEF operations */
#endif

#ifdef NXPBUILD__PHPAL_I18000P3M3_SW
    #define NXPBUILD__PHAL_I18000P3M3_SW                        /**< AL ISO18000p3m3 SW Component is included */
#endif /* NXPBUILD__PHPAL_I18000P3M3_SW */

#ifdef NXPBUILD__PHPAL_I14443P4MC_SW
    #if !defined(PH_OSAL_NULLOS)
        #define NXPBUILD__PHCE_T4T_SW                           /**< AL HCE T2AT SW Component is included */
        /*#define NXPBUILD__PHCE_T4T_PROPRIETARY*/              /**< SRC to handle HCE T4AT Proprietary Commands is included */
        /*#define NXPBUILD__PHCE_T4T_EXT_NDEF */                /**< SRC to handle Extended NDEF Support as per T4T spec 3.0 is included */
    #endif
#endif /* NXPBUILD__PHPAL_I14443P4MC_SW */

/* LLCP Components */
#if defined(NXPBUILD__PHPAL_I18092MPI_SW) || \
    defined(NXPBUILD__PHPAL_I18092MT_SW)
    #if !defined(PH_OSAL_NULLOS)
        #define NXPBUILD__PHLN_LLCP_SW                          /**< Link LLCP SW Component is included */
    #endif
#endif

/* SNEP components */
#ifdef NXPBUILD__PHLN_LLCP_SW
    #define NXPBUILD__PHNP_SNEP_SW                              /**< Protocol SNEP SW Component is included */
#endif /* NXPBUILD__PHLN_LLCP_SW */

/* Enable/disable Debugging */
/*#define NXPBUILD__PH_DEBUG*/

/** @}
* end of ph_NxpBuild
*/

#endif /* PH_NXPBUILD_LPC_H */
