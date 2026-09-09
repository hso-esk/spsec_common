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

#ifndef PLATFORM_SYSTEM_H
#define PLATFORM_SYSTEM_H

// Wires the OS "please stop" event to a portable callback (SIGINT/SIGTERM
// on Linux; hook a GPIO/watchdog or no-op on a microcontroller).

// on_stop_ptr runs on shutdown request; must be async-signal-safe on Linux
// (it should only set a flag).
void platform_request_stop_on_signal(void (*on_stop_ptr)(void));

#endif // PLATFORM_SYSTEM_H
