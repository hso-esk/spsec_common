/*
 * Copyright (c) 2026
 *
 * Hochschule Offenburg, University of Applied Sciences
 * Institute for reliable Embedded Systems
 * and Communications Electronic (ivESK)
 *
 * This file is licensed as described in the "LICENSE" file
 * included within the root folder of this work.
 */

#ifndef LED_STATUS_H
#define LED_STATUS_H

#include "spsec_registers.h"
#include <stdbool.h>

// LED status indication for the SPsec state machine. Currently just logs
// the state changes; embedded ports should drive real LEDs here.

// Update LEDs for the current SPsec state per SPsec302 V40 Section 8.1:
// not-active=red on, waiting=green blink 200/800ms, secure=green on,
// warning=red+green alternate 400ms, configuration=green blink 800/200ms.
void led_status_update(spsec_state_t state, bool alert_flag);

signed char led_status_init(void);

void led_status_cleanup(void);

#endif // LED_STATUS_H
