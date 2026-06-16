module GPGME
  # Data encoding
  DATA_ENCODING_NONE   = 0_u32
  DATA_ENCODING_BINARY = 1_u32
  DATA_ENCODING_BASE64 = 2_u32
  DATA_ENCODING_ARMOR  = 3_u32
  DATA_ENCODING_URL    = 4_u32
  DATA_ENCODING_URLESC = 5_u32
  DATA_ENCODING_URL0   = 6_u32
  DATA_ENCODING_MIME   = 7_u32

  # Protocols
  PROTOCOL_OpenPGP = 0_u32
  PROTOCOL_CMS     = 1_u32

  # Keylist modes
  KEYLIST_MODE_LOCAL         =   1_u32
  KEYLIST_MODE_EXTERN        =   2_u32
  KEYLIST_MODE_SIGS          =   4_u32
  KEYLIST_MODE_VALIDATE      = 256_u32
  KEYLIST_MODE_SIG_NOTATIONS =   8_u32
  KEYLIST_MODE_EPHEMERAL     = 128_u32
  KEYLIST_MODE_WITH_SECRET   =  16_u32

  # Encrypt flags
  ENCRYPT_ALWAYS_TRUST  =  1_u32
  ENCRYPT_NO_ENCRYPT_TO =  2_u32
  ENCRYPT_PREPARE       =  4_u32
  ENCRYPT_EXPECT_SIGN   =  8_u32
  ENCRYPT_NO_COMPRESS   = 16_u32
  ENCRYPT_SYMMETRIC     = 32_u32
  ENCRYPT_THROW_KEYIDS  = 64_u32

  # Import flags
  IMPORT_NEW    =  1_u32
  IMPORT_UID    =  2_u32
  IMPORT_SIG    =  4_u32
  IMPORT_SUBKEY =  8_u32
  IMPORT_SECRET = 16_u32

  # Signature modes
  SIG_MODE_NORMAL = 0_u32
  SIG_MODE_DETACH = 1_u32
  SIG_MODE_CLEAR  = 2_u32

  # Signature summary
  SIGSUM_VALID       = 0x0001_u32
  SIGSUM_GREEN       = 0x0002_u32
  SIGSUM_RED         = 0x0004_u32
  SIGSUM_KEY_REVOKED = 0x0010_u32
  SIGSUM_KEY_EXPIRED = 0x0020_u32
  SIGSUM_SIG_EXPIRED = 0x0040_u32
  SIGSUM_KEY_MISSING = 0x0080_u32
  SIGSUM_CRL_MISSING = 0x0100_u32
  SIGSUM_CRL_TOO_OLD = 0x0200_u32
  SIGSUM_BAD_POLICY  = 0x0400_u32
  SIGSUM_SYS_ERROR   = 0x0800_u32

  # Pinentry modes
  PINENTRY_MODE_DEFAULT  = 0_u32
  PINENTRY_MODE_ASK      = 1_u32
  PINENTRY_MODE_CANCEL   = 2_u32
  PINENTRY_MODE_ERROR    = 3_u32
  PINENTRY_MODE_LOOPBACK = 4_u32

  PINENTRY_MODE_NAMES = {
    PINENTRY_MODE_DEFAULT  => :default,
    PINENTRY_MODE_ASK      => :ask,
    PINENTRY_MODE_CANCEL   => :cancel,
    PINENTRY_MODE_ERROR    => :error,
    PINENTRY_MODE_LOOPBACK => :loopback,
  }

  # Delete flags
  DELETE_ALLOW_SECRET = 1_u32
  DELETE_FORCE        = 2_u32

  # Validity
  VALIDITY_UNKNOWN   = 0
  VALIDITY_UNDEFINED = 1
  VALIDITY_NEVER     = 2
  VALIDITY_MARGINAL  = 3
  VALIDITY_FULL      = 4
  VALIDITY_ULTIMATE  = 5

  VALIDITY_NAMES = {
    VALIDITY_UNKNOWN   => :unknown,
    VALIDITY_UNDEFINED => :undefined,
    VALIDITY_NEVER     => :never,
    VALIDITY_MARGINAL  => :marginal,
    VALIDITY_FULL      => :full,
    VALIDITY_ULTIMATE  => :ultimate,
  }

  # Public key algorithms
  PK_RSA   =   1
  PK_RSA_E =   2
  PK_RSA_S =   3
  PK_DSA   =  17
  PK_ECC   =  18
  PK_ELG_E =  16
  PK_ELG   =  20
  PK_ECDSA = 301
  PK_ECDH  = 302
  PK_EDDSA = 303

  # Hash algorithms
  MD_NONE          =   0
  MD_MD5           =   1
  MD_SHA1          =   2
  MD_RMD160        =   3
  MD_MD2           =   5
  MD_TIGER         =   6
  MD_HAVAL         =   7
  MD_SHA256        =   8
  MD_SHA384        =   9
  MD_SHA512        =  10
  MD_SHA224        =  11
  MD_MD4           = 301
  MD_CRC32         = 302
  MD_CRC32_RFC1510 = 303
  MD_CRC24_RFC2440 = 304

  # Signature status (gpg-error codes used in signature status)
  GPG_ERR_NO_ERROR              =     0_u32
  GPG_ERR_GENERAL               =     1_u32
  GPG_ERR_BAD_SIGNATURE         =     8_u32
  GPG_ERR_NO_PUBKEY             =     9_u32
  GPG_ERR_BAD_PASSPHRASE        =    11_u32
  GPG_ERR_NO_SECKEY             =    17_u32
  GPG_ERR_UNUSABLE_PUBKEY       =    53_u32
  GPG_ERR_UNUSABLE_SECKEY       =    54_u32
  GPG_ERR_INV_VALUE             =    55_u32
  GPG_ERR_BAD_CERT_CHAIN        =    56_u32
  GPG_ERR_MISSING_CERT          =    57_u32
  GPG_ERR_NO_DATA               =    58_u32
  GPG_ERR_NOT_IMPLEMENTED       =    69_u32
  GPG_ERR_CONFLICT              =    70_u32
  GPG_ERR_UNSUPPORTED_ALGORITHM =    84_u32
  GPG_ERR_CERT_REVOKED          =    94_u32
  GPG_ERR_NO_CRL_KNOWN          =    95_u32
  GPG_ERR_CANCELED              =    99_u32
  GPG_ERR_CERT_EXPIRED          =   101_u32
  GPG_ERR_AMBIGUOUS_NAME        =   107_u32
  GPG_ERR_NO_POLICY_MATCH       =   116_u32
  GPG_ERR_WRONG_KEY_USAGE       =   125_u32
  GPG_ERR_INV_ENGINE            =   150_u32
  GPG_ERR_DECRYPT_FAILED        =   152_u32
  GPG_ERR_KEY_EXPIRED           =   153_u32
  GPG_ERR_SIG_EXPIRED           =   154_u32
  GPG_ERR_EOF                   = 16383_u32
  GPG_ERR_ENOMEM                = (1_u32 << 15) | 86_u32

  # Protocol names
  PROTOCOL_NAMES = {
    PROTOCOL_OpenPGP => "OpenPGP",
    PROTOCOL_CMS     => "CMS",
  }

  # Keylist mode names
  KEYLIST_MODE_NAMES = {
    KEYLIST_MODE_LOCAL    => "local",
    KEYLIST_MODE_EXTERN   => "extern",
    KEYLIST_MODE_SIGS     => "sigs",
    KEYLIST_MODE_VALIDATE => "validate",
  }

  # Random modes
  RANDOM_MODE_NORMAL  = 0_u32
  RANDOM_MODE_ZBASE32 = 1_u32
end
