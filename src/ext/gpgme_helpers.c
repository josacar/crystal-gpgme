/* gpgme_helpers.c -- C accessors for GPGME structs with bitfields.
 *
 * Crystal cannot directly represent C bitfields in lib bindings, so this
 * small helper library exposes plain getters/setters for the fields used by
 * crystal-gpgme.
 *
 * This file is a part of crystal-gpgme and is licensed under the same
 * LGPL-2.1-or-later terms as the project.
 */

#include <gpgme.h>

/* ---------------------------------------------------------------------- */
/* Engine info                                                            */
/* ---------------------------------------------------------------------- */

gpgme_engine_info_t cgpgme_engine_info_next(gpgme_engine_info_t info)
{
  return info ? info->next : NULL;
}

int cgpgme_engine_info_protocol(gpgme_engine_info_t info)
{
  return info ? info->protocol : 0;
}

const char *cgpgme_engine_info_file_name(gpgme_engine_info_t info)
{
  return info ? info->file_name : NULL;
}

const char *cgpgme_engine_info_version(gpgme_engine_info_t info)
{
  return info ? info->version : NULL;
}

const char *cgpgme_engine_info_req_version(gpgme_engine_info_t info)
{
  return info ? info->req_version : NULL;
}

const char *cgpgme_engine_info_home_dir(gpgme_engine_info_t info)
{
  return info ? info->home_dir : NULL;
}

/* ---------------------------------------------------------------------- */
/* Key                                                                    */
/* ---------------------------------------------------------------------- */

#define KEY_GETTER(type, field) \
  type cgpgme_key_get_##field(gpgme_key_t key) { return key ? key->field : 0; }

KEY_GETTER(int, revoked)
KEY_GETTER(int, expired)
KEY_GETTER(int, disabled)
KEY_GETTER(int, invalid)
KEY_GETTER(int, can_encrypt)
KEY_GETTER(int, can_sign)
KEY_GETTER(int, can_certify)
KEY_GETTER(int, secret)
KEY_GETTER(int, can_authenticate)
KEY_GETTER(int, protocol)
KEY_GETTER(int, owner_trust)
KEY_GETTER(unsigned int, keylist_mode)

const char *cgpgme_key_get_issuer_serial(gpgme_key_t key)
{
  return key ? key->issuer_serial : NULL;
}

const char *cgpgme_key_get_issuer_name(gpgme_key_t key)
{
  return key ? key->issuer_name : NULL;
}

const char *cgpgme_key_get_chain_id(gpgme_key_t key)
{
  return key ? key->chain_id : NULL;
}

const char *cgpgme_key_get_fpr(gpgme_key_t key)
{
  return key ? key->fpr : NULL;
}

gpgme_subkey_t cgpgme_key_get_subkeys(gpgme_key_t key)
{
  return key ? key->subkeys : NULL;
}

gpgme_user_id_t cgpgme_key_get_uids(gpgme_key_t key)
{
  return key ? key->uids : NULL;
}

/* ---------------------------------------------------------------------- */
/* Subkey                                                                 */
/* ---------------------------------------------------------------------- */

#define SUBKEY_GETTER(type, field) \
  type cgpgme_subkey_get_##field(gpgme_subkey_t sk) { return sk ? sk->field : 0; }

SUBKEY_GETTER(int, revoked)
SUBKEY_GETTER(int, expired)
SUBKEY_GETTER(int, disabled)
SUBKEY_GETTER(int, invalid)
SUBKEY_GETTER(int, can_encrypt)
SUBKEY_GETTER(int, can_sign)
SUBKEY_GETTER(int, can_certify)
SUBKEY_GETTER(int, can_authenticate)
SUBKEY_GETTER(int, secret)
SUBKEY_GETTER(int, pubkey_algo)
SUBKEY_GETTER(unsigned int, length)
SUBKEY_GETTER(unsigned long, timestamp)
SUBKEY_GETTER(unsigned long, expires)

const char *cgpgme_subkey_get_keyid(gpgme_subkey_t sk)
{
  return sk ? sk->keyid : NULL;
}

const char *cgpgme_subkey_get_fpr(gpgme_subkey_t sk)
{
  return sk ? sk->fpr : NULL;
}

const char *cgpgme_subkey_get_curve(gpgme_subkey_t sk)
{
  return sk ? sk->curve : NULL;
}

gpgme_subkey_t cgpgme_subkey_next(gpgme_subkey_t sk)
{
  return sk ? sk->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* User ID                                                                */
/* ---------------------------------------------------------------------- */

#define UID_GETTER(type, field) \
  type cgpgme_uid_get_##field(gpgme_user_id_t uid) { return uid ? uid->field : 0; }

UID_GETTER(int, revoked)
UID_GETTER(int, invalid)
UID_GETTER(int, validity)

const char *cgpgme_uid_get_uid(gpgme_user_id_t uid)
{
  return uid ? uid->uid : NULL;
}

const char *cgpgme_uid_get_name(gpgme_user_id_t uid)
{
  return uid ? uid->name : NULL;
}

const char *cgpgme_uid_get_email(gpgme_user_id_t uid)
{
  return uid ? uid->email : NULL;
}

const char *cgpgme_uid_get_comment(gpgme_user_id_t uid)
{
  return uid ? uid->comment : NULL;
}

gpgme_key_sig_t cgpgme_uid_get_signatures(gpgme_user_id_t uid)
{
  return uid ? uid->signatures : NULL;
}

gpgme_user_id_t cgpgme_uid_next(gpgme_user_id_t uid)
{
  return uid ? uid->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Key signature                                                          */
/* ---------------------------------------------------------------------- */

#define KEYSIG_GETTER(type, field) \
  type cgpgme_keysig_get_##field(gpgme_key_sig_t ks) { return ks ? ks->field : 0; }

KEYSIG_GETTER(int, revoked)
KEYSIG_GETTER(int, expired)
KEYSIG_GETTER(int, invalid)
KEYSIG_GETTER(int, exportable)
KEYSIG_GETTER(int, pubkey_algo)
KEYSIG_GETTER(unsigned long, timestamp)
KEYSIG_GETTER(unsigned long, expires)

const char *cgpgme_keysig_get_keyid(gpgme_key_sig_t ks)
{
  return ks ? ks->keyid : NULL;
}

gpgme_key_sig_t cgpgme_keysig_next(gpgme_key_sig_t ks)
{
  return ks ? ks->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Signature (verify result)                                              */
/* ---------------------------------------------------------------------- */

#define SIG_GETTER(type, field) \
  type cgpgme_signature_get_##field(gpgme_signature_t sig) { return sig ? sig->field : 0; }

SIG_GETTER(unsigned int, summary)
SIG_GETTER(gpgme_error_t, status)
SIG_GETTER(unsigned long, timestamp)
SIG_GETTER(unsigned long, exp_timestamp)
SIG_GETTER(int, wrong_key_usage)
SIG_GETTER(int, pka_trust)
SIG_GETTER(int, validity)
SIG_GETTER(gpgme_error_t, validity_reason)
SIG_GETTER(int, pubkey_algo)
SIG_GETTER(int, hash_algo)

const char *cgpgme_signature_get_fpr(gpgme_signature_t sig)
{
  return sig ? sig->fpr : NULL;
}

const char *cgpgme_signature_get_pka_address(gpgme_signature_t sig)
{
  return sig ? sig->pka_address : NULL;
}

gpgme_key_t cgpgme_signature_get_key(gpgme_signature_t sig)
{
  return sig ? sig->key : NULL;
}

gpgme_signature_t cgpgme_signature_next(gpgme_signature_t sig)
{
  return sig ? sig->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Decrypt result                                                         */
/* ---------------------------------------------------------------------- */

const char *cgpgme_decrypt_result_get_unsupported_algorithm(gpgme_decrypt_result_t res)
{
  return res ? res->unsupported_algorithm : NULL;
}

int cgpgme_decrypt_result_get_wrong_key_usage(gpgme_decrypt_result_t res)
{
  return res ? res->wrong_key_usage : 0;
}

const char *cgpgme_decrypt_result_get_file_name(gpgme_decrypt_result_t res)
{
  return res ? res->file_name : NULL;
}

gpgme_recipient_t cgpgme_decrypt_result_get_recipients(gpgme_decrypt_result_t res)
{
  return res ? res->recipients : NULL;
}

/* ---------------------------------------------------------------------- */
/* Recipient                                                              */
/* ---------------------------------------------------------------------- */

const char *cgpgme_recipient_get_keyid(gpgme_recipient_t rec)
{
  return rec ? rec->keyid : NULL;
}

int cgpgme_recipient_get_pubkey_algo(gpgme_recipient_t rec)
{
  return rec ? rec->pubkey_algo : 0;
}

gpgme_error_t cgpgme_recipient_get_status(gpgme_recipient_t rec)
{
  return rec ? rec->status : 0;
}

gpgme_recipient_t cgpgme_recipient_next(gpgme_recipient_t rec)
{
  return rec ? rec->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Sign result                                                            */
/* ---------------------------------------------------------------------- */

gpgme_invalid_key_t cgpgme_sign_result_get_invalid_signers(gpgme_sign_result_t res)
{
  return res ? res->invalid_signers : NULL;
}

gpgme_new_signature_t cgpgme_sign_result_get_signatures(gpgme_sign_result_t res)
{
  return res ? res->signatures : NULL;
}

/* ---------------------------------------------------------------------- */
/* New signature                                                          */
/* ---------------------------------------------------------------------- */

#define NEWSIG_GETTER(type, field) \
  type cgpgme_newsig_get_##field(gpgme_new_signature_t ns) { return ns ? ns->field : 0; }

NEWSIG_GETTER(int, type)
NEWSIG_GETTER(int, pubkey_algo)
NEWSIG_GETTER(int, hash_algo)
NEWSIG_GETTER(unsigned int, sig_class)
NEWSIG_GETTER(unsigned long, timestamp)

const char *cgpgme_newsig_get_fpr(gpgme_new_signature_t ns)
{
  return ns ? ns->fpr : NULL;
}

gpgme_new_signature_t cgpgme_newsig_next(gpgme_new_signature_t ns)
{
  return ns ? ns->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Encrypt result                                                         */
/* ---------------------------------------------------------------------- */

gpgme_invalid_key_t cgpgme_encrypt_result_get_invalid_recipients(gpgme_encrypt_result_t res)
{
  return res ? res->invalid_recipients : NULL;
}

/* ---------------------------------------------------------------------- */
/* Invalid key                                                            */
/* ---------------------------------------------------------------------- */

const char *cgpgme_invalid_key_get_fpr(gpgme_invalid_key_t ik)
{
  return ik ? ik->fpr : NULL;
}

const char *cgpgme_strerror(gpgme_error_t err)
{
  return gpgme_strerror(err);
}

gpgme_error_t cgpgme_invalid_key_get_reason(gpgme_invalid_key_t ik)
{
  return ik ? ik->reason : 0;
}

gpgme_invalid_key_t cgpgme_invalid_key_next(gpgme_invalid_key_t ik)
{
  return ik ? ik->next : NULL;
}

/* ---------------------------------------------------------------------- */
/* Verify result                                                          */
/* ---------------------------------------------------------------------- */

gpgme_signature_t cgpgme_verify_result_get_signatures(gpgme_verify_result_t res)
{
  return res ? res->signatures : NULL;
}

const char *cgpgme_verify_result_get_file_name(gpgme_verify_result_t res)
{
  return res ? res->file_name : NULL;
}

int cgpgme_verify_result_get_is_mime(gpgme_verify_result_t res)
{
  return res ? res->is_mime : 0;
}

/* ---------------------------------------------------------------------- */
/* Import result                                                          */
/* ---------------------------------------------------------------------- */

#define IMPRES_GETTER(type, field) \
  type cgpgme_import_result_get_##field(gpgme_import_result_t res) { return res ? res->field : 0; }

IMPRES_GETTER(int, considered)
IMPRES_GETTER(int, no_user_id)
IMPRES_GETTER(int, imported)
IMPRES_GETTER(int, imported_rsa)
IMPRES_GETTER(int, unchanged)
IMPRES_GETTER(int, new_user_ids)
IMPRES_GETTER(int, new_sub_keys)
IMPRES_GETTER(int, new_signatures)
IMPRES_GETTER(int, new_revocations)
IMPRES_GETTER(int, secret_read)
IMPRES_GETTER(int, secret_imported)
IMPRES_GETTER(int, secret_unchanged)
IMPRES_GETTER(int, not_imported)

gpgme_import_status_t cgpgme_import_result_get_imports(gpgme_import_result_t res)
{
  return res ? res->imports : NULL;
}

/* ---------------------------------------------------------------------- */
/* Import status                                                          */
/* ---------------------------------------------------------------------- */

const char *cgpgme_import_status_get_fpr(gpgme_import_status_t st)
{
  return st ? st->fpr : NULL;
}

gpgme_error_t cgpgme_import_status_get_result(gpgme_import_status_t st)
{
  return st ? st->result : 0;
}

unsigned int cgpgme_import_status_get_status(gpgme_import_status_t st)
{
  return st ? st->status : 0;
}

gpgme_import_status_t cgpgme_import_status_next(gpgme_import_status_t st)
{
  return st ? st->next : NULL;
}
