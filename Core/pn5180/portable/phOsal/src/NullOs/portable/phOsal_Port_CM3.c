/*
 * phOsal_Port_CM3.c
 * This file contains TickTimer related functionality implementation required
 * by the NullOs. Below depends on LPC_OPEN and is being tested for LPC1769.
 *
 *  Created on: Jan 31, 2017
 *      Author: nxf18375
 */

#include "phOsal.h"
#include "phOsal_NullOs_Port.h"

//1     #ifdef PH_OSAL_NULLOS
#include "phOsal_Cortex_Port.h"

#ifdef __GNUC__
    #define __ENABLE_IRQ() __asm volatile ("cpsie i")
    #define __DISABLE_IRQ() __asm volatile ("cpsid i")
    #define __WFE() __asm volatile ("wfe")
    #define __SEV() __asm volatile ("sev")
#endif /* __GNUC__ */


#ifdef __ARMCC_VERSION
    #define __ENABLE_IRQ __enable_irq
    #define __DISABLE_IRQ __disable_irq
    #define __WFE __wfe
    #define __SEV __sev
#endif /* __ARMCC_VERSION */

#ifdef __ICCARM__
#   include "intrinsics.h"
#   define __NOP             __no_operation
#   define __ENABLE_IRQ      __enable_interrupt
#   define __DISABLE_IRQ     __disable_interrupt
#endif

#define SYSTICK_TIMER_MAX           0xFFFFFFU    /* [23:0] bits Timer. */
#define SYSTICK_TIMER_CLK           0x00000004
#define SYSTICK_TIMER_INT           0x00000002
#define SYSTICK_TIMER_ENABLE        0x00000001

#define PH_PLATFORM_TIMER_UNIT_MS       1000U      /**< Indicates that the specified delay is in milliseconds. */

static pphOsal_TickTimerISRCallBck_t pTickCallBack;
static  uint64_t qwLoadValue;

/* Timer rate. */
static uint32_t dwSysTickTimerFreq;

#if defined(__GNUC__) || defined (__ARMCC_VERSION) || defined (__ICCARM__)
/* In case some assembler gets smart to include this file, it would not
 * complain about extern */
extern uint32_t SystemCoreClock;
#endif

phStatus_t phOsal_InitTickTimer(pphOsal_TickTimerISRCallBck_t pTickTimerCallback)
{
    pTickCallBack = pTickTimerCallback;

    qwLoadValue = 0;

    /* SysTick Timer rate is system clock rate. */
    dwSysTickTimerFreq = SystemCoreClock;

    /* Disable systick and clear the Load value. */
    SysTick->CTRL = 0x0;
    SysTick->LOAD = 0x0;

    return PH_OSAL_SUCCESS;
}

static void phOsal_ConfigTick(void)
{
    /* Disable systick */
    SysTick->CTRL = 0x0;

    /* Configure SysTick count down value to interrupt at the requested time. */
    if(qwLoadValue > SYSTICK_TIMER_MAX)
    {
        qwLoadValue -= SYSTICK_TIMER_MAX;
        SysTick->LOAD = SYSTICK_TIMER_MAX;
    }
    else
    {
        SysTick->LOAD = (uint32_t)(qwLoadValue & SYSTICK_TIMER_MAX);
        qwLoadValue = 0;
    }

    /*Clear the current count value and also SysTick CTRL.COUNTFLAG. */
    SysTick->VAL = 0;

    SysTick->CTRL = SYSTICK_TIMER_CLK | SYSTICK_TIMER_INT | SYSTICK_TIMER_ENABLE;
}

phStatus_t phOsal_StartTickTimer(uint32_t dwTimeMilliSecs)
{
    qwLoadValue = ((uint64_t)dwTimeMilliSecs * (uint64_t)dwSysTickTimerFreq)/PH_PLATFORM_TIMER_UNIT_MS;

    phOsal_ConfigTick();

    return PH_OSAL_SUCCESS;
}

phStatus_t phOsal_StopTickTimer(void)
{
    /* Disable systick and clear the Load value. */
    SysTick->CTRL = 0x0;
    SysTick->LOAD = 0x0;

    return PH_OSAL_SUCCESS;
}

void phOsal_EnterCriticalSection(void)
{
    __DISABLE_IRQ();
}

void phOsal_ExitCriticalSection(void)
{
    __ENABLE_IRQ();
}

void phOsal_Sleep(void)
{
    __WFE();
}

void phOsal_WakeUp(void)
{
    __SEV();
}

void phOsal_SysTick_Handler(void)               //1
{
    if(qwLoadValue)
    {
        if(qwLoadValue > SYSTICK_TIMER_MAX)
        {
            qwLoadValue -= SYSTICK_TIMER_MAX;
        }
        else
        {
            /* Timer to be configured. */
            phOsal_ConfigTick();
        }
    }
    else
    {
        /* Stop the Timer and call the callBack. */
        phOsal_StopTickTimer();

        pTickCallBack();
    }
}
//1     #endif /*PH_OSAL_NULLOS*/

