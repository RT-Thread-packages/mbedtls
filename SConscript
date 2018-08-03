from building import *
import rtconfig
Import('RTT_ROOT')

cwd = GetCurrentDir()
src = Glob('mbedtls/library/*.c')
SrcRemove(src, 'mbedtls/library/net_sockets.c')

src += Glob('ports/src/*.c')

if GetDepend(['PKG_USING_MBEDTLS_EXAMPLE']):
    src += Glob('examples/*.c')
    
CPPPATH = [
cwd + '/mbedtls/include',
cwd + '/mbedtls/include/mbedtls',
cwd + '/ports/inc',
]

if rtconfig.CROSS_TOOL == 'gcc' :
    CPPDEFINES = ['MBEDTLS_CONFIG_FILE=\\"tls_config.h\\"']
elif rtconfig.CROSS_TOOL == 'keil' or rtconfig.CROSS_TOOL == 'iar':
    import shutil
    cp_src = cwd + '/ports/inc/tls_config.h'
    cp_dst = cwd + '/mbedtls/include/mbedtls/config.h'
    shutil.copyfile(cp_src, cp_dst)
    CPPDEFINES = []
else:
    CPPDEFINES = []

group = DefineGroup('mbedtls', src, depend = ['PKG_USING_MBEDTLS'], CPPPATH = CPPPATH, CPPDEFINES = CPPDEFINES)

Return('group')
