from building import *
Import('RTT_ROOT')

cwd = GetCurrentDir()
src = Glob('mbedtls/library/*.c')
SrcRemove(src, 'net_sockets.c')

src += Glob('mbedtls-port/src/*.c')

if GetDepend(['PKG_USING_MBEDTLS_EXAMPLE']):
    src += Glob('examples/*.c')
    
CPPPATH = [
cwd,
cwd + '/mbedtls/include',
cwd + '/mbedtls/include/mbedtls',
cwd + '/mbedtls-port/inc',
]
CPPPATH += [RTT_ROOT + '/include/libc']

CPPDEFINES = ['MBEDTLS_CONFIG_FILE=\\"tls_config.h\\"']

group = DefineGroup('mbedtls', src, depend = ['PKG_USING_MBEDTLS'], CPPPATH = CPPPATH, CPPDEFINES = CPPDEFINES)

Return('group')
