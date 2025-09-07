/**
 * SPDX-FileCopyrightText: 2021-2024 Infineon Technologies AG
 * SPDX-License-Identifier: MIT
 *
 * \author Infineon Technologies AG
 *
 * \file pal_os_event.h
 *
 * \brief   This file provides the prototype declarations of PAL OS event
 *
 * \ingroup  grPAL
 *
 * @{
 */

#ifndef _PAL_OS_EVENT_H_
#define _PAL_OS_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "optiga_lib_types.h"

typedef uint16_t pal_status_t;  // or use the actual type from optiga_lib_types.h

/**
 * \brief typedef for Callback function when timer elapses.
 */
typedef void (*register_callback)(void *);

/** \brief PAL os event structure */
typedef struct pal_os_event {
    /// context to be passed to callback
    void *callback_ctx;
    /// os timer
    void *os_timer;
    /// event triggered status
    bool_t is_event_triggered;
    /// Holds the next event timeout value in microseconds
    uint32_t timeout_us;
    /// To synchronize between events
    uint8_t sync_flag;
    /// registered callback
    register_callback callback_registered;
} pal_os_event_t;

/**
 * \brief Create an os event.
 */
LIBRARY_EXPORTS pal_os_event_t *
pal_os_event_create(register_callback callback, void *callback_args);

/**
 * \brief Destroys an os event.
 */
LIBRARY_EXPORTS void pal_os_event_destroy(pal_os_event_t *pal_os_event);

/**
 * \brief Callback registration function to trigger once when timer expires.
 */
LIBRARY_EXPORTS void pal_os_event_register_callback_oneshot(
    pal_os_event_t *p_pal_os_event,
    register_callback callback,
    void *callback_args,
    uint32_t time_us
);

/**
 * \brief Timer callback handler.
 */
void pal_os_event_trigger_registered_callback(void);

/**
 * \brief Start an os event.
 */
LIBRARY_EXPORTS void
pal_os_event_start(pal_os_event_t *p_pal_os_event, register_callback callback, void *callback_args);

/**
 * \brief Stops an os event.
 */
LIBRARY_EXPORTS void pal_os_event_stop(pal_os_event_t *p_pal_os_event);

/**
 * \brief Initialize PAL OS event system.
 *
 * \return PAL_STATUS_SUCCESS on success, PAL_STATUS_FAILURE otherwise.
 */
LIBRARY_EXPORTS pal_status_t pal_os_event_init(void);

#ifdef __cplusplus
}
#endif

#endif /*_PAL_OS_EVENT_H_*/

/**
 * @}
 */
