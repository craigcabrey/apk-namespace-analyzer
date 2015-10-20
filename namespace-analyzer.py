#!/usr/bin/env python3

import argparse
import re
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile


def extract_namespaces(source_path, base_namespace=''):
    namespaces = set()

    for entry in os.listdir(source_path):
        full_path = os.path.join(source_path, entry)
        if os.path.isdir(full_path):
            new_namespace = '{0}{1}'.format(base_namespace, entry)
            namespaces.add(new_namespace)
            sub_namespaces = extract_namespaces(full_path, new_namespace + '.')
            namespaces = namespaces.union(sub_namespaces)

    return namespaces


def convert_to_jar(dex2jar_path, directory):
    dex_path = os.path.join(directory, 'classes.dex')
    jar_path = os.path.join(directory, 'classes.jar')
    cmd = [dex2jar_path, '-e', '/dev/null', '-o', jar_path, dex_path]
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
    if b'Detail Error Information in File' in output:
        # Workaround for dex2jar not properly setting a return code on failure
        raise subprocess.CalledProcessError(1, cmd)
    return jar_path


def process_apk(config, apk_path):
    with tempfile.TemporaryDirectory(dir=config.working_directory) as tmp_dir:
        with zipfile.ZipFile(apk_path) as apk_zip:
            print('==> Extracting classes.dex... ', end='')
            apk_zip.extract('classes.dex', path=tmp_dir)
            print('done.')

        try:
            print('==> Converting classes.dex to classes.jar...', end='')
            jar_path = convert_to_jar(config.dex2jar_path, tmp_dir)
            print('done.')
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print('failed.\n[ERROR] Failed to convert dex into jar.')
            return []

        with zipfile.ZipFile(jar_path) as jar_zip:
            print('==> Extracting JAR classes... ', end='')
            jar_zip.extractall(path=tmp_dir)
            print('done.')

        return extract_namespaces(tmp_dir)


def process_apks(config):
    apk_regex = re.compile('^([^-]+)-?(\d*)?-(\d{4}_\d{2}_\d{2})\.apk$',
                    re.IGNORECASE)

    items = os.listdir(config.path)
    total = len(items)
    current = 1
    for name in items:
        apk_path = os.path.join(config.path, name)
        print(':: Processing {0} of {1}: '.format(current, total), end='')
        match = apk_regex.match(name)
        if os.path.isfile(apk_path) and match:
            insert_apk(config, match)
            print(match.group(1))
            namespaces = process_apk(config, apk_path)
            insert_namespaces(config, match.group(1), namespaces)
        else:
            print('{0} is not an APK'.format(name))
        current += 1


def insert_namespaces(config, apk_id, namespaces):
    cur = config.db.cursor()

    # TODO: use executemany instead of looping with execute
    for namespace in namespaces:
        cur.execute('''
        INSERT INTO namespaces
            (apk_id, body)
            VALUES(?, ?)
        ''', (apk_id, namespace))

    cur.close()


def insert_apk(config, match):
    cur = config.db.cursor()

    cur.execute('''
    INSERT INTO apks
        (id, date, filename)
        VALUES(?, ?, ?)
    ''', (match.group(1), match.group(3), match.group(0)))

    cur.close()

def init_database(config):
    config.db = sqlite3.connect(config.db_filename)
    cur = config.db.cursor()

    cur.execute('''
    CREATE TABLE IF NOT EXISTS apks
    (
        id text,
        date text,
        filename text
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS namespaces
    (
        apk_id text,
        body text,
        FOREIGN KEY(apk_id) REFERENCES apks(id)
    )
    ''')

    cur.close()


err_msg = '{0} is not a valid path'
def dir(argument):
    if not os.path.exists(argument):
        raise argparse.ArgumentTypeError(err_msg.format(argument))

    return argument


def file(argument):
    path = os.path.abspath(argument)
    if not os.path.exists(path):
        if not os.path.exists(os.path.dirname(path)):
            raise argparse.ArgumentTypeError(err_msg.format(argument))

    return argument

def executable(argument):
    if not shutil.which(argument):
        if not os.path.exists(argument):
            raise argparse.ArgumentTypeError(err_msg.format(argument))

    return argument


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Script to unpackage, extract, and analyze a directory ' \
                    'of APKs in order to determine the usage of namespaces.'
    )
    parser.add_argument(
        'path',
        type=dir,
        help='Path to the directory with the APKs.'
    )
    parser.add_argument(
        '--database',
        dest='db_filename',
        default='results.sqlite',
        metavar='PATH',
        type=file,
        help='Name of the resulting SQLite database filename.'
    )
    parser.add_argument(
        '--dex2jar',
        dest='dex2jar_path',
        default='dex2jar',
        metavar='PATH',
        type=executable,
        help='Path to the `dex2jar\' executable.'
    )
    parser.add_argument(
        '--working-dir',
        dest='working_directory',
        default='/tmp',
        metavar='PATH',
        type=dir,
        help='Path to the working directory in which to extract and analyze ' \
             'each APK.'
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    config = parse_arguments()
    init_database(config)
    process_apks(config)
    config.db.commit()
    config.db.close()

if __name__ == '__main__':
    main()
