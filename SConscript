from building import *
import rtconfig
import shutil
import os
import sys
import subprocess
import importlib.util
from string import Template

Import('RTT_ROOT')

# 1. Specific certificate file template
cert_template = """
/*
 * Copyright (c) 2006-2018 RT-Thread Development Team. All rights reserved.
 * License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stddef.h>

const char mbedtls_root_certificate[] = 
"-----BEGIN CERTIFICATE-----\\r\\n\" \\
"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\\r\\n" \\
"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\\r\\n" \\
"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\\r\\n" \\
"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\\r\\n" \\
"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\\r\\n" \\
"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\\r\\n" \\
"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\\r\\n" \\
"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\\r\\n" \\
"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\\r\\n" \\
"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\\r\\n" \\
"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\\r\\n" \\
"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\\r\\n" \\
"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\\r\\n" \\
"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\\r\\n" \\
"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\\r\\n" \\
"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\\r\\n" \\
"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\\r\\n" \\
"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\\r\\n" \\
"-----END CERTIFICATE-----\\r\\n" \\
${CERT_CONTENT}
;

const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);

"""

# 2. Create substitute from template
cert_subs = Template(cert_template)

# 3. Get the current absolute path
cwd = GetCurrentDir()

# 4. PEM certificate file path (*.pem or *.cer)
certs_user_dir = cwd + os.sep + 'certs'
certs_default_dir = cwd + os.sep + (os.sep).join(['certs', 'default'])

ROOT_CA_FILE = []

# 5. File that stores the contents of the certificate file
output_cert_file = cwd + os.sep + (os.sep).join(['ports', 'src', 'tls_certificate.c'])

if GetDepend('PKG_USING_MBEDTLS_EXAMPLE'):
    path = cwd + os.sep + (os.sep).join(['certs', 'default', 'DIGITAL_SIGNATURE_TRUST_ROOT_CA.cer'])
    if os.path.exists(path):
        ROOT_CA_FILE += [path]

if GetDepend('PKG_USING_MBEDTLS_USE_ALL_CERTS'):
    file_list = os.listdir(certs_default_dir)
    if len(file_list):
        for i in range(0, len(file_list)):
            path = os.path.join(certs_default_dir, file_list[i])
            if os.path.isfile(path):
                ROOT_CA_FILE += [path]

if GetDepend('PKG_USING_MBEDTLS_USER_CERTS'):
    file_list = os.listdir(certs_user_dir)
    if len(file_list):
        for i in range(0, len(file_list)):
            path = os.path.join(certs_user_dir, file_list[i])
            if os.path.isfile(path):
                ROOT_CA_FILE += [path]


KCONFIG_ROOT_CA_DICT = [('PKG_USING_MBEDTLS_THAWTE_ROOT_CA', 'THAWTE_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_VERSIGN_PBULIC_ROOT_CA', 'VERSIGN_PUBLIC_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_VERSIGN_UNIVERSAL_ROOT_CA', 'VERSIGN_UNIVERSAL_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_GEOTRUST_ROOT_CA', 'GEOTRUST_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_DIGICERT_ROOT_CA', 'DIGICERT_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_GODADDY_ROOT_CA', 'GODADDY_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_COMODOR_ROOT_CA', 'COMODOR_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_DST_ROOT_CA', 'DIGITAL_SIGNATURE_TRUST_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_CLOBALSIGN_ROOT_CA', 'CLOBALSIGN_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_ENTRUST_ROOT_CA', 'ENTRUST_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_CERTUM_TRUSTED_NETWORK_ROOT_CA', 'CERTUM_TRUSTED_NETWORK_ROOT_CA.cer'), \
                        ('PKG_USING_MBEDTLS_AMAZON_ROOT_CA', 'AMAZON_ROOT_CA.cer')]

for PKG_key, value in KCONFIG_ROOT_CA_DICT:
    if GetDepend(PKG_key):
        path = os.path.join(certs_default_dir, value)
        if os.path.exists(path) and os.path.isfile(path):
            ROOT_CA_FILE += [path]

ROOT_CA_FILE = list(set(ROOT_CA_FILE))

file_content = ""

# 6. Traverse the specified certificate file
if len(ROOT_CA_FILE) > 0:
    for i in range(0, len(ROOT_CA_FILE)):
        if os.path.isfile(ROOT_CA_FILE[i]):
            # READ CER FILE, copy to tls_certificate.c
            with open(ROOT_CA_FILE[i], 'rb') as ca:
                content = ca.read()

            if not content.startswith(b"-----BEGIN CERTIFICATE"):
                print("[mbedtls] Warning: ", ROOT_CA_FILE[i], "is not PEM CA file! Skipped!")
                continue

            text = content.decode('utf-8', errors='ignore')
            for line in text.splitlines():
                file_content += '"' + line.strip() + '\\r\\n" \\\n'

# 7. Populate certificate template content
cert_content = cert_subs.substitute(CERT_CONTENT = file_content)

# 8. Write certificate template content to tls_certificate.c
with open(output_cert_file, 'w', encoding='utf-8') as f:
    f.write(cert_content)


# Ensure mbedtls generated wrapper files exist before source collection.
# If dependencies are missing, install from scripts/basic.requirements.txt first.
def _ensure_driver_wrapper_generated(root_dir):
    """Generate PSA driver wrapper sources required by mbedtls 3.x when missing."""
    mbedtls_root = os.path.join(root_dir, 'mbedtls')
    wrapper_h = os.path.join(mbedtls_root, 'library', 'psa_crypto_driver_wrappers.h')
    wrapper_c = os.path.join(mbedtls_root, 'library', 'psa_crypto_driver_wrappers_no_static.c')

    if os.path.exists(wrapper_h) and os.path.exists(wrapper_c):
        return

    requirements = os.path.join(mbedtls_root, 'scripts', 'basic.requirements.txt')
    required_modules = ['jsonschema', 'jinja2']
    missing_modules = [m for m in required_modules if importlib.util.find_spec(m) is None]

    if missing_modules and os.path.exists(requirements):
        print('[mbedtls] Installing Python dependencies from scripts/basic.requirements.txt...')
        try:
            subprocess.check_call([
                sys.executable,
                '-m',
                'pip',
                'install',
                '--disable-pip-version-check',
                '-r',
                requirements,
            ])
        except Exception as err:
            print('[mbedtls] Error: failed to install Python dependencies:', err)
            Exit(1)

    script = os.path.join(mbedtls_root, 'scripts', 'generate_driver_wrappers.py')
    cmd = [sys.executable, script]

    print('[mbedtls] Generating PSA driver wrapper files...')
    try:
        subprocess.check_call(cmd, cwd=mbedtls_root)
    except Exception as err:
        print('[mbedtls] Error: failed to generate PSA driver wrapper files:', err)
        Exit(1)


_ensure_driver_wrapper_generated(cwd)


src = Glob('mbedtls/library/*.c')
SrcRemove(src, 'mbedtls/library/net_sockets.c')

src += Glob('ports/src/*.c')

if GetDepend('PKG_USING_MBEDTLS_EXAMPLE'):
    src += Glob('samples/*.c')

CPPPATH = [
cwd + '/mbedtls/include',
cwd + '/mbedtls/library',
cwd + '/ports/inc',
]

CPPDEFINES = ['MBEDTLS_CONFIG_FILE=<tls_config.h>']

group = DefineGroup('mbedtls', src, depend = ['PKG_USING_MBEDTLS'], CPPPATH = CPPPATH, CPPDEFINES = CPPDEFINES)

Return('group')
