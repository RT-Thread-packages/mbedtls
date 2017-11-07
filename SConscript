from building import *
Import('RTT_ROOT')

cwd = GetCurrentDir()
src = Split('''
mbedtls/library/havege.c
mbedtls/library/ssl_cookie.c
mbedtls/library/md5.c
mbedtls/library/certs.c
mbedtls/library/ssl_ciphersuites.c
mbedtls/library/camellia.c

mbedtls/library/threading.c
mbedtls/library/aesni.c
mbedtls/library/bignum.c
mbedtls/library/arc4.c
mbedtls/library/cipher_wrap.c
mbedtls/library/aes.c
mbedtls/library/xtea.c
mbedtls/library/base64.c
mbedtls/library/sha512.c
mbedtls/library/pkcs11.c
mbedtls/library/asn1write.c
mbedtls/library/oid.c
mbedtls/library/ecjpake.c
mbedtls/library/ssl_tls.c
mbedtls/library/debug.c
mbedtls/library/ecdh.c

mbedtls/library/ssl_srv.c
mbedtls/library/ecdsa.c
mbedtls/library/md2.c

mbedtls/library/memory_buffer_alloc.c
mbedtls/library/gcm.c
mbedtls/library/version.c
mbedtls/library/pem.c
mbedtls/library/padlock.c
mbedtls/library/asn1parse.c

mbedtls/library/ssl_cli.c
mbedtls/library/pkwrite.c
mbedtls/library/ssl_cache.c
mbedtls/library/sha256.c
mbedtls/library/md_wrap.c
mbedtls/library/entropy.c
mbedtls/library/md.c
mbedtls/library/rsa.c
mbedtls/library/ripemd160.c
mbedtls/library/version_features.c
mbedtls/library/cipher.c

mbedtls/library/dhm.c
mbedtls/library/error.c
mbedtls/library/ssl_ticket.c
mbedtls/library/blowfish.c
mbedtls/library/ecp.c
mbedtls/library/md4.c
mbedtls/library/pkparse.c
mbedtls/library/pkcs5.c
mbedtls/library/ccm.c
mbedtls/library/pkcs12.c
mbedtls/library/ecp_curves.c
mbedtls/library/pk_wrap.c
mbedtls/library/ctr_drbg.c
mbedtls/library/platform.c
mbedtls/library/pk.c
mbedtls/library/des.c
mbedtls/library/hmac_drbg.c
mbedtls/library/sha1.c
mbedtls/library/x509_crl.c
mbedtls/library/x509_create.c

mbedtls/library/x509.c
mbedtls/library/x509_csr.c
mbedtls/library/x509write_crt.c
mbedtls/library/x509write_csr.c

port/timing.c
mbedtls/library/x509_crt.c
port/entropy_poll.c

tls_net.c

''')

# mbedtls/library/net_sockets.c

CPPPATH = [
cwd,
cwd + '/port/include',
cwd + '/mbedtls/include',
cwd + '/mbedtls/include/mbedtls',
]
CPPPATH += [RTT_ROOT + '/include/libc']

LOCAL_CPPDEFINES = ['MBEDTLS_CONFIG_FILE=\\"mbedtls/rtt_config.h\\"', 'HAVE_CONFIG_H']

group = DefineGroup('mbedtls', src, depend = ['PKG_USING_MBEDTLS'], CPPPATH = CPPPATH, LOCAL_CPPDEFINES = LOCAL_CPPDEFINES)

Return('group')
