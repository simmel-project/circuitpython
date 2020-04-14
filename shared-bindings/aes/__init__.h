/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Scott Shawcroft for Adafruit Industries
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef MICROPY_INCLUDED_SHARED_BINDINGS_AES_H
#define MICROPY_INCLUDED_SHARED_BINDINGS_AES_H

#include "shared-module/aes/__init__.h"

extern const mp_obj_type_t aes_aes_type;

void common_hal_aes_construct(aes_obj_t* self,
                              const uint8_t* key,
                              uint32_t key_length,
                              const uint8_t* iv,
                              int mode,
                              int counter);
void common_hal_aes_rekey(aes_obj_t* self,
                          const uint8_t* key,
                          uint32_t key_length,
                          const uint8_t* iv);
void common_hal_aes_set_mode(aes_obj_t* self,
                             int mode);
void common_hal_aes_encrypt(aes_obj_t* self,
                            uint8_t* buffer,
                            size_t len);
void common_hal_aes_decrypt(aes_obj_t* self,
                            uint8_t* buffer,
                            size_t len);

#endif // MICROPY_INCLUDED_SHARED_BINDINGS_AES_H
