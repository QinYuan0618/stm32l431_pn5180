/*
 * phOsal_Config.h
 *
 *  Created on: Jan 6, 2017
 *      Author: nxf18375
 */

#ifndef PHOSAL_INC_PHOSAL_CONFIG_H_
#define PHOSAL_INC_PHOSAL_CONFIG_H_

/** \defgroup phOsal_Config OSAL Config
* \brief This defines various Config Options for the OSAL
* @{
*/

/**
* @{
* @def PH_OSAL_NULLOS
*      Macro to Enable NULLOS Support
* @def PH_OSAL_FREERTOS
*      Macro to Enable FreeRTOS Support
*
* @def PH_OSAL_LINUX
*      Macro to Enable Linux Support
*
*/
/*@}*/


/**
 *\brief If RTOS supports Static Memory Allocation and it is Enabled.
 * Below mentioned define Max limit for creation of resources.
 *
 * @{
 * @def PH_OSAL_CONFIG_MAX_NUM_TASKS
 *
 *        Maximum No of Statically Created Tasks
 * @def PH_OSAL_CONFIG_MAX_NUM_EVENTS
 *
 *        Maximum No of Statically Created Tasks
 * @def PH_OSAL_CONFIG_MAX_NUM_SEMAPHORE
 *
 *        Maximum No of Statically Created Semaphores
 * @def PH_OSAL_CONFIG_MAX_NUM_MUTEX
 *
 *        Maximum No of Statically Created Mutex
 * @def PH_OSAL_CONFIG_MAX_NUM_TIMERS
 *
 *        Maximum No of Statically Created Timers
 */
/*@}*/


/* Select one of the phOsal Implementation through defined symbols (-D). */

#ifdef PH_OSAL_FREERTOS

#include "../src/Freertos/phOsal_Freertos.h"

#define PH_OSAL_CONFIG_MAX_NUM_TASKS       4U
#define PH_OSAL_CONFIG_MAX_NUM_EVENTS      3U
#define PH_OSAL_CONFIG_MAX_NUM_SEMAPHORE   8U
#define PH_OSAL_CONFIG_MAX_NUM_MUTEX       2U
#define PH_OSAL_CONFIG_MAX_NUM_TIMERS      2U

#endif /* PH_OSAL_FREERTOS */


//1     #ifdef PH_OSAL_NULLOS

#include "../src/NullOs/phOsal_NullOs.h"

#define PH_OSAL_CONFIG_MAX_NUM_EVENTS        5U

//1     #endif /* PH_OSAL_NULLOS */


#ifdef PH_OSAL_LINUX

#include "../src/Linux/phOsal_Linux.h"

#define PH_OSAL_CONFIG_LINUX_MAX_NUM_TASKS          5U
#define PH_OSAL_CONFIG_LINUX_MAX_NUM_EVENTS         5U

#endif /* PH_OSAL_LINUX */

#ifndef PHOSAL_MAX_DELAY
//#   error "OSAL not selected"
#endif

/*@}*/
#endif /* PHOSAL_INC_PHOSAL_CONFIG_H_ */
