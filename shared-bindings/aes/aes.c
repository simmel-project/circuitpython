#include <stdint.h>
#include <string.h>

#include "py/obj.h"
#include "py/runtime.h"

#include "shared-bindings/aes/__init__.h"

// Defined at the end of this file

//| .. currentmodule:: aes
//|
//| :class:`aes` -- Encrypt and decrypt AES streams
//| =====================================================
//|
//| An object that represents an AES stream, including the current state.
//|
//| .. class:: AES(key[, mode, iv])
//|
//|   Create a new AES state with the given key.
//|
//|   :param bytearray key: A 16-, 24-, or 32-byte key
//|   :param int mode: AES mode to use.  One of: AES.MODE_ECB, AES.MODE_CBC, or
//|                    AES.MODE_CTR
//|   :param bytearray iv: Initialization vector to use for CBC or CTR mode
//|
//|   Additional arguments are supported for legacy reasons.
//|
//|   Encrypting a string::
//|
//|     import aes
//|     from binascii import hexlify
//|
//|     key = b'Sixteen byte key'
//|     cipher = new aes(key, aes.mode.MODE_ECB)
//|     hexlify(cipher.encrypt(b'Circuit Python!!'))
//|

STATIC mp_obj_t aes_make_new(const mp_obj_type_t *type, size_t n_args,
                             const mp_obj_t *pos_args, mp_map_t *kw_args) {
  (void)type;
  enum { ARG_key, ARG_mode, ARG_IV, ARG_counter, ARG_segment_size };
  static const mp_arg_t allowed_args[] = {
      {MP_QSTR_key, MP_ARG_OBJ | MP_ARG_REQUIRED},
      {MP_QSTR_mode, MP_ARG_INT},
      {MP_QSTR_IV, MP_ARG_OBJ},
      {MP_QSTR_counter, MP_ARG_OBJ},
      {MP_QSTR_segment_size, MP_ARG_INT},
  };
  mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];

  // Set defaults. These will be overridden in mp_arg_parse_all() if an
  // argument is provided.
  args[ARG_mode].u_int = 0;
  args[ARG_IV].u_obj = NULL;
  args[ARG_counter].u_int = 0;
  args[ARG_segment_size].u_int =
      8; // Only useful in CFB mode, which we don't support
  mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args),
                   allowed_args, args);

  aes_obj_t *self = m_new_obj(aes_obj_t);
  self->base.type = &aes_aes_type;

  mp_buffer_info_t bufinfo;

  const uint8_t *key = NULL;
  uint32_t key_length = 0;
  if (mp_get_buffer(args[ARG_key].u_obj, &bufinfo, MP_BUFFER_READ)) {
    if ((bufinfo.len != 16) && (bufinfo.len != 24) && (bufinfo.len != 32)) {
      mp_raise_TypeError(translate("Key must be 16, 24, or 32 bytes long"));
    }
    key = bufinfo.buf;
    key_length = bufinfo.len;
  } else {
    mp_raise_TypeError(translate("No key was specified"));
  }

  int mode = args[ARG_mode].u_int;
  switch (args[ARG_mode].u_int) {
  case AES_MODE_CBC: /* CBC */
    break;
  case AES_MODE_ECB: /* ECB */
    break;
  case AES_MODE_CTR: /* CTR */
    break;
  case 0:
    mode = AES_MODE_ECB;
    break;
  default:
    mp_raise_TypeError(translate("Requested AES mode is unsupported"));
  }

  // IV is required for CBC mode and is ignored for other modes.
  const uint8_t *iv = NULL;
  if (args[ARG_IV].u_obj != NULL &&
      mp_get_buffer(args[ARG_IV].u_obj, &bufinfo, MP_BUFFER_READ)) {
    if (bufinfo.len != AES_BLOCKLEN) {
      mp_raise_TypeError_varg(translate("IV must be %d bytes long"),
                              AES_BLOCKLEN);
    }
    iv = bufinfo.buf;
  }

  common_hal_aes_construct(self, key, key_length, iv, mode,
                           args[ARG_counter].u_int);
  return MP_OBJ_FROM_PTR(self);
}

STATIC mp_obj_t aes_rekey(size_t n_args, const mp_obj_t *pos_args) {
  aes_obj_t *self = MP_OBJ_TO_PTR(pos_args[0]);

  size_t key_length = 0;
  const uint8_t *key = (const uint8_t *)mp_obj_str_get_data(pos_args[1], &key_length);
  if (key == NULL) {
    mp_raise_ValueError(translate("No key was specified"));
  }
  if ((key_length != 16) && (key_length != 24) && (key_length != 32)) {
    mp_raise_TypeError(translate("Key must be 16, 24, or 32 bytes long"));
  }

  const uint8_t *iv = NULL;
  if (n_args > 2) {
    size_t iv_length = 0;
    iv = (const uint8_t *)mp_obj_str_get_data(pos_args[2], &iv_length);
    if (iv_length != AES_BLOCKLEN) {
      mp_raise_TypeError_varg(translate("IV must be %d bytes long"),
                              AES_BLOCKLEN);
    }
  }

  common_hal_aes_rekey(self, key, key_length, iv);
  return mp_const_none;
}

MP_DEFINE_CONST_FUN_OBJ_VAR(aes_rekey_obj, 2, aes_rekey);


STATIC mp_obj_t aes_set_mode(mp_obj_t aes_obj, mp_obj_t mode_obj) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *self = MP_OBJ_TO_PTR(aes_obj);

  int mode = mp_obj_get_int(mode_obj);
  switch (mode) {
  case AES_MODE_CBC: /* CBC */
    break;
  case AES_MODE_ECB: /* ECB */
    break;
  case AES_MODE_CTR: /* CTR */
    break;
  default:
    mp_raise_TypeError(translate("Requested AES mode is unsupported"));
  }

  common_hal_aes_set_mode(self, mode);
  return mp_const_none;
}

MP_DEFINE_CONST_FUN_OBJ_2(aes_set_mode_obj, aes_set_mode);


STATIC byte *duplicate_data(const byte *src_buf, size_t len) {
  byte *dest_buf = m_new(byte, len);
  memcpy(dest_buf, src_buf, len);
  return dest_buf;
}

//|   .. method:: encrypt_in_place(buf)
//|
//|      Encrypt the provided buffer in-place without copying it first.
//|      The buffer must be a multiple of 16 bytes.
//|
STATIC mp_obj_t aes_encrypt_in_place(mp_obj_t aes_obj, mp_obj_t buf) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);
  mp_buffer_info_t bufinfo;
  mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_READ);
  if ((bufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }

  common_hal_aes_encrypt(aes, (uint8_t *)bufinfo.buf, bufinfo.len);
  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(aes_encrypt_in_place_obj,
                                 aes_encrypt_in_place);

//|   .. method:: encrypt_into(src, dest)
//|
//|      Encrypt the buffer from ``src`` into ``dest``.
//|      The buffers must be a multiple of 16 bytes, and must
//|      be equal length
//|
STATIC mp_obj_t aes_encrypt_into(mp_obj_t aes_obj, mp_obj_t src,
                                 mp_obj_t dest) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);

  mp_buffer_info_t srcbufinfo;
  mp_get_buffer_raise(src, &srcbufinfo, MP_BUFFER_READ);
  if ((srcbufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }

  mp_buffer_info_t destbufinfo;
  mp_get_buffer_raise(dest, &destbufinfo, MP_BUFFER_READ);
  if (destbufinfo.len != srcbufinfo.len) {
    mp_raise_ValueError(
        translate("Source and destination buffers must be the same length"));
  }

  memcpy(destbufinfo.buf, srcbufinfo.buf, srcbufinfo.len);

  common_hal_aes_decrypt(aes, (uint8_t *)destbufinfo.buf, destbufinfo.len);
  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(aes_encrypt_into_obj, aes_encrypt_into);

//|   .. method:: encrypt(buf)
//|
//|      Encrypt the buffer and return a copy of the encrypted data.
//|      The buffer must be a multiple of 16 bytes.
//|
STATIC mp_obj_t aes_encrypt(mp_obj_t aes_obj, mp_obj_t buf) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);
  mp_buffer_info_t bufinfo;
  mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_READ);
  if ((bufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }

  byte *dest_buf = duplicate_data((const byte *)bufinfo.buf, bufinfo.len);
  common_hal_aes_encrypt(aes, (uint8_t *)dest_buf, bufinfo.len);

  return mp_obj_new_bytearray_by_ref(bufinfo.len, dest_buf);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(aes_encrypt_obj, aes_encrypt);

//|   .. method:: decrypt_in_place(buf)
//|
//|      Decrypt the provided buffer in-place without copying it first.
//|      The buffer must be a multiple of 16 bytes.
//|
STATIC mp_obj_t aes_decrypt_in_place(mp_obj_t aes_obj, mp_obj_t buf) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);
  mp_buffer_info_t bufinfo;
  mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_READ);
  if ((bufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }
  common_hal_aes_decrypt(aes, (uint8_t *)bufinfo.buf, bufinfo.len);
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(aes_decrypt_in_place_obj,
                                 aes_decrypt_in_place);

//|   .. method:: decrypt_into(src, dest)
//|
//|      Decrypt the buffer from ``src`` into ``dest``.
//|      The buffers must be a multiple of 16 bytes, and must
//|      be equal length
//|
STATIC mp_obj_t aes_decrypt_into(mp_obj_t aes_obj, mp_obj_t src,
                                 mp_obj_t dest) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);

  mp_buffer_info_t srcbufinfo;
  mp_get_buffer_raise(src, &srcbufinfo, MP_BUFFER_READ);
  if ((srcbufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }

  mp_buffer_info_t destbufinfo;
  mp_get_buffer_raise(dest, &destbufinfo, MP_BUFFER_READ);
  if (destbufinfo.len != srcbufinfo.len) {
    mp_raise_ValueError(
        translate("Source and destination buffers must be the same length"));
  }

  memcpy(destbufinfo.buf, srcbufinfo.buf, srcbufinfo.len);

  common_hal_aes_decrypt(aes, (uint8_t *)destbufinfo.buf, destbufinfo.len);
  return mp_const_none;
}

STATIC MP_DEFINE_CONST_FUN_OBJ_3(aes_decrypt_into_obj, aes_decrypt_into);

//|   .. method:: decrypt(buf)
//|
//|      Decrypt the buffer and return a copy of the decrypted data.
//|      The buffer must be a multiple of 16 bytes.
//|
STATIC mp_obj_t aes_decrypt(mp_obj_t aes_obj, mp_obj_t buf) {
  if (!MP_OBJ_IS_TYPE(aes_obj, &aes_aes_type)) {
    mp_raise_TypeError_varg(translate("Expected a %q"), aes_aes_type.name);
  }
  // Convert parameters into expected types.
  aes_obj_t *aes = MP_OBJ_TO_PTR(aes_obj);
  mp_buffer_info_t bufinfo;
  mp_get_buffer_raise(buf, &bufinfo, MP_BUFFER_READ);
  if ((bufinfo.len & (AES_BLOCKLEN - 1)) != 0) {
    mp_raise_ValueError(translate("Buffer must be a multiple of 16 bytes"));
  }

  byte *dest_buf = duplicate_data((const byte *)bufinfo.buf, bufinfo.len);
  common_hal_aes_decrypt(aes, (uint8_t *)dest_buf, bufinfo.len);
  return mp_obj_new_bytearray_by_ref(bufinfo.len, dest_buf);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(aes_decrypt_obj, aes_decrypt);

STATIC const mp_rom_map_elem_t aes_locals_dict_table[] = {
    // Methods
    {MP_ROM_QSTR(MP_QSTR___name__), MP_OBJ_NEW_QSTR(MP_QSTR_AES)},
    {MP_ROM_QSTR(MP_QSTR_encrypt), (mp_obj_t)&aes_encrypt_obj},
    {MP_ROM_QSTR(MP_QSTR_decrypt), (mp_obj_t)&aes_decrypt_obj},
    {MP_ROM_QSTR(MP_QSTR_encrypt_in_place),
     (mp_obj_t)&aes_encrypt_in_place_obj},
    {MP_ROM_QSTR(MP_QSTR_decrypt_in_place),
     (mp_obj_t)&aes_decrypt_in_place_obj},
    {MP_ROM_QSTR(MP_QSTR_encrypt_into), (mp_obj_t)&aes_encrypt_into_obj},
    {MP_ROM_QSTR(MP_QSTR_decrypt_into), (mp_obj_t)&aes_decrypt_into_obj},
    {MP_ROM_QSTR(MP_QSTR_rekey), (mp_obj_t)&aes_rekey_obj},
    {MP_ROM_QSTR(MP_QSTR_set_mode), (mp_obj_t)&aes_set_mode_obj},
};
STATIC MP_DEFINE_CONST_DICT(aes_locals_dict, aes_locals_dict_table);

const mp_obj_type_t aes_aes_type = {
    {&mp_type_type},
    .name = MP_QSTR_AES,
    .make_new = aes_make_new,
    .locals_dict = (mp_obj_dict_t *)&aes_locals_dict,
};
