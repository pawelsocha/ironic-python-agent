#!/usr/bin/env python2.7

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import shutil
import subprocess
import sys
import tempfile
import time

import requests

COREOS_VERSION = "master"

COREOS_ARCH = "amd64-usr"
COREOS_BASE_URL = ("http://storage.core-os.net/coreos/{arch}/{ver}"
                   .format(arch=COREOS_ARCH, ver=COREOS_VERSION))
COREOS_PXE_DIGESTS = "coreos_production_pxe_image.cpio.gz.DIGESTS.asc"
COREOS_PXE_KERNEL = "coreos_production_pxe.vmlinuz"
COREOS_PXE_IMAGE = "coreos_production_pxe_image.cpio.gz"
COREOS_PXE_IMAGE_URL = "{url}/{img}".format(url=COREOS_BASE_URL,
                                            img=COREOS_PXE_IMAGE)
COREOS_PXE_KERNEL_URL = "{url}/{kernel}".format(url=COREOS_BASE_URL,
                                                kernel=COREOS_PXE_KERNEL)
COREOS_PXE_DIGESTS_URL = "{url}/{digests}".format(url=COREOS_BASE_URL,
                                                  digests=COREOS_PXE_DIGESTS)


def get_etag(cache_name):
    etag_file = "{}.etag".format(cache_name)
    if not os.path.exists(etag_file):
        return None
    with open(etag_file, 'rb') as fp:
        etag = fp.read()
    etag.strip()
    return etag


def save_etag(cache_name, etag):
    etag_file = "{}.etag".format(cache_name)
    with open(etag_file, 'w+b') as fp:
        fp.write(etag)


def cache_file(cache_name, remote_url):
    print("{cname} <- {url}".format(cname=cache_name, url=remote_url))
    etag = get_etag(cache_name)
    headers = {}
    if etag:
        headers['If-None-Match'] = etag

    start = time.time()
    r = requests.get(remote_url, headers=headers)

    if r.status_code == 304:
        print("[etag-match]")
        return

    if r.status_code != 200:
        raise RuntimeError('Failed to download {url}, got HTTP {code} Status '
                           'Code.'.format(url=remote_url, code=r.status_code))

    with open(cache_name, 'w+b') as fp:
        fp.write(r.content)

    print("{length} bytes in {timespan} seconds"
          .format(length=len(r.content), timespan=time.time() - start))
    save_etag(cache_name, r.headers['etag'])


def inject_oem(archive, oem_dir, output_file):
    d = tempfile.mkdtemp(prefix="oem-inject")
    try:
        dest_oem_dir = os.path.join(d, 'usr', 'share', 'oem')
        cmd_chain = 'gunzip -c {} | cpio -iv'.format(archive)
        execute(cmd_chain, shell=True, cwd=d)

        shutil.copytree(oem_dir, dest_oem_dir)

        cmd_chain = 'find . -depth -print | sort | cpio -o -H newc | ' \
                    'gzip > {}'.format(output_file)
        execute(cmd_chain, shell=True, cwd=d)
    finally:
        shutil.rmtree(d)
    return output_file


def validate_digests(digests, target, hash_type='sha1'):
    cmd_chain = 'grep -i -A1 "^# {htype} HASH$" {digests} | grep {tgt} | ' \
                '{htype}sum -c /dev/stdin'.format(htype=hash_type,
                                                  digests=digests,
                                                  tgt=os.path.basename(target))
    execute(cmd_chain, shell=True, cwd=os.path.dirname(digests))


def main():
    if len(sys.argv) != 3:
        print("usage: {} [oem-directory-to-inject] [output-directory]"
              .format(os.path.basename(__file__)))
        return

    oem_dir = os.path.abspath(os.path.expanduser(sys.argv[1]))
    output_dir = os.path.abspath(os.path.expanduser(sys.argv[2]))

    if not os.path.exists(oem_dir):
        print("Error: {} doesn't exist.".format(oem_dir))
        return

    if not os.path.exists(os.path.join(oem_dir, 'cloud-config.yml')):
        print("Error: {} is missing cloud-config.yml".format(oem_dir))
        return

    here = os.path.abspath(os.path.dirname(__file__))

    top_cache_dir = os.path.join(os.path.dirname(here), ".image_cache")
    cache_dir = os.path.join(top_cache_dir, COREOS_ARCH, COREOS_VERSION)

    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)

    orig_cpio = os.path.join(cache_dir, COREOS_PXE_IMAGE)
    digests = os.path.join(cache_dir, COREOS_PXE_DIGESTS)
    kernel = os.path.join(cache_dir, COREOS_PXE_KERNEL)

    cache_file(digests, COREOS_PXE_DIGESTS_URL)
    gpg_verify_file(digests)
    cache_file(kernel, COREOS_PXE_KERNEL_URL)
    validate_digests(digests, kernel)
    cache_file(orig_cpio, COREOS_PXE_IMAGE_URL)
    validate_digests(digests, orig_cpio)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_kernel = os.path.join(output_dir, os.path.basename(kernel))
    output_cpio = os.path.join(
        output_dir,
        os.path.basename(orig_cpio).replace('.cpio.gz', '-oem.cpio.gz'))
    inject_oem(orig_cpio, oem_dir, output_cpio)
    shutil.copy(kernel, output_kernel)


def gpg_verify_file(ascfile):
    d = tempfile.mkdtemp(prefix="oem-gpg-validate")

    r = requests.get(
        'https://coreos.com/security/image-signing-key/'\
        'CoreOS_Image_Signing_Key.asc')

    assert r.status_code == 200,\
        'Error downloading CoreOs GPG Sing Key. Http Code={}'.format(r.status_code)


    try:
        tmpring = os.path.join(d, 'tmp.gpg')
        key = os.path.join(d, 'coreos.key')

        with open(key, 'w+b') as fp:
            fp.write(r.text)

        execute(['gpg', '--batch', '--no-default-keyring',
                 '--keyring', tmpring, '--import', key])

        execute(['gpg', '--batch', '--no-default-keyring',
                 '--keyring', tmpring, '--verify', ascfile])

    finally:
        shutil.rmtree(d)


def execute(cmd, shell=False, cwd=None):
    popen_obj = subprocess.Popen(cmd, shell=shell, cwd=cwd)
    popen_obj.communicate()
    if popen_obj.returncode != 0:
        raise subprocess.CalledProcessError(returncode=popen_obj.returncode,
                                            cmd=cmd)

if __name__ == "__main__":
    main()
