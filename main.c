/**
 * MSP430FR6989 Authenticator
 *
 * This software implements RFC 4226: HMAC-Based One-Time Password Algorithm
 * on the EXP-MSP430FR6989 development board.
 *
 *
 * Copyright 2017, Kate Gray
 *
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
 */
#include <driverlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "helper.h"
#include "memory.h"
#include "hal_LCD.h"

extern int hmac_sha1 (const void *key, size_t keylen,
    const void *in, size_t inlen, void *resbuf);

// Counter
#pragma PERSISTENT(counter)
unsigned char counter[8] = {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};

int main(void) {
    // Used to select which portion of the HMAC gets selected for the OTP
    // This ensures that an attacker doesn't know what portion of the HMAC is
    // used, denying them any information whatsoever for brute-forcing the
    // counter or secret.
    uint8_t offset = 0u;

    // Stores the extracted OTP for processing
    uint8_t OTP[4] = {0u, 0u, 0u, 0u};
    uint32_t OTP_decimal;

    // Stores the formatted OTP
    char OTP_text[HOTP_DIGITS + 1];

    // Test vector from RFC 4226, "12345678901234567890"
    const unsigned char secret[SECRET_SIZE] = {
        0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u, 0x38u,
        0x39u, 0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u,
        0x37u, 0x38u, 0x39u, 0x30u
    };

    // Stores the computed HMAC
    unsigned char hmac[SHA1_BLOCKSIZE];

    // Disable the watchdog timer completely (it's not needed for this project)
    WDT_A_hold(WDT_A_BASE);

    // Helper functions from the TI Out-Of-Box demo
    Init_GPIO();
    Init_Clock();
    Init_LCD();

    // Initialize the HMAC memory area
    memset (hmac, 0, sizeof(hmac));

    // Calculate the HMAC
    hmac_sha1 (&secret, sizeof(secret), (const void*)&counter, sizeof(counter), hmac);

    // Truncate the HMAC for compliance with OATH standards.
    offset = (hmac[19] & 0x0fu);

    // Swap the bytes (due to endianness) and strip the MSB (the spec requires this to avoid sign issues)
    OTP[3] = hmac[offset] & 0x7fu;
    OTP[2] = hmac[offset+1u];
    OTP[1] = hmac[offset+2u];
    OTP[0] = hmac[offset+3u];

    // Casting won't work right with TI's compiler, so memcpy the bytes after putting them in the proper order
    memcpy(&OTP_decimal, &OTP, sizeof(OTP_decimal));
    OTP_decimal %= HOTP_MODULO;

    sprintf (OTP_text, HOTP_FORMAT, OTP_decimal);

    // Increment the persistent counter (in a big-endian way)
    if (counter[7] == 0xffu) {
        if (counter[6] == 0xffu) {
            if (counter[5] == 0xffu) {
                if (counter[4] == 0xffu) {
                    if (counter[3] == 0xffu) {
                        if (counter[2] == 0xffu) {
                            if (counter[1] == 0xffu) {
                                counter[0]++;
                            }
                            counter[1]++;
                        }
                        counter[2]++;
                    }
                    counter[3]++;
                }
                counter[4]++;
            }
            counter[5]++;
        }
        counter[6]++;
    }
    counter[7]++;

    // Hello, World
    clearLCD();
    displayScrollText(OTP_text);

    return (0);
}

