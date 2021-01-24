import requests
import time
import os
import shutil
import hashlib
import logging


config = {
    'url': 'https://www.someonewhocares.org/hosts/hosts',
    'blocked_domains_file': 'named.conf.blockeddomains',
    'additional_domains_file': 'additional_domains',
    'current_additional_domains_file': '.cad',
    'raw_parsed_file': '.raw',
    'fresh_blacklist_file': '.fbl',
    'stale_blacklist_file': '.sbl',
    'wait_time': 10,
    'blocked_domains_target_path': '/etc/named/'
}

FORMAT = '%(asctime)s: %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
logger = logging.getLogger()

def apply_bind_format(line):
    prefix = 'zone "'
    suffix = '" {type master; file "named.empty";};'
    return f'{prefix}{line}{suffix}'


def parse_blocked_domain(line):
    # remove first part of the line which includes the 127.0.0.1 address
    line = line[10:]

    # remove new new lines characters
    line = line.replace("\n", "")

    # trim anything beyond the domain name
    for character in [' ', '\t']:
        if character in line:
            line = line[0:line.index(character)]

    # remove unwanted characters
    for character in ['#', '@']:
        if character in line:
            line = line.replace(character, ' ')

    # strip whitespaces from edges
    line = line.strip()

    return apply_bind_format(line)


def process_blocked_domains_list(data):
    new_lines = []
    skip_list = ['localhost', 'local']

    for line in data:
        if '127.0.0.1' not in line:
            continue

        if any(item in line for item in skip_list):
            continue

        if str.startswith(line, '#'):
            continue

        entry = parse_blocked_domain(line)
        new_lines.append(entry)
    return new_lines


def process_additional_domains_list(data):
    new_lines = []
    for line in data:
        new_lines.append(apply_bind_format(line))
    return new_lines


def create_domain_list_file():
    logger.debug(f"Downloading domain list from {config['url']}")
    r = requests.get(config['url'], stream=True)

    with open(config['fresh_blacklist_file'], 'wb') as domain_list:
        logger.debug('Writing domain list to local file')
        for chunk in r.iter_content(chunk_size=80):
            if chunk:
                domain_list.write(chunk)


def get_hash(item):
    hasher = hashlib.sha1()
    hasher.update(item)
    return hasher.hexdigest()


def has_diff():
    if not os.path.exists(config['stale_blacklist_file']):
        return False

    logger.info('Checking for diff in fresh and stale blacklist file hashes')
    with open(config['fresh_blacklist_file'], 'rb') as afile:
        buf = afile.read()
        hash1 = get_hash(buf)
    logger.debug(f"{config['fresh_blacklist_file']} hash: {hash1}")

    with open(config['stale_blacklist_file'], 'rb') as afile:
        buf = afile.read()
        hash2 = get_hash(buf)
    logger.debug(f"{config['stale_blacklist_file']} hash: {hash2}")

    if hash1 != hash2:
        logger.info("A diff in hashes has been found!")
        return True
    logger.debug("Hashes are identical")
    return False


def read_file_to_list(path):
    try:
        f = open(path, 'r')
        as_list = f.read().splitlines()
        f.close()
        return as_list
    except FileNotFoundError:
        logger.warning(f'File {path} not found. Returning empty list...')
        return []


def has_new_additional_domains():
    additional_domains = read_file_to_list(config['additional_domains_file'])
    cad = read_file_to_list(config['current_additional_domains_file'])
    logger.debug(f'Desired additional domains: {additional_domains}')
    logger.debug(f'Current additional domains: {cad}')

    if len(additional_domains) != len(cad):
        logger.info('Additional domains have been found!')
        write_current_additional_domains()
        return True
    return False


def write_current_additional_domains():
    additional_domains = read_file_to_list(config['additional_domains_file'])
    with open(config['current_additional_domains_file'], 'w') as cad_output:
        for line in additional_domains:
            cad_output.write(f'{line}\n')


def process_new_hosts():
    with open(config['fresh_blacklist_file'], 'r', encoding='utf-8-sig') as raw:
        data = raw.read().splitlines(True)
    additional_domains = read_file_to_list(config['additional_domains_file'])

    blocked_domains = process_blocked_domains_list(data) + process_additional_domains_list(additional_domains)

    with open(config['raw_parsed_file'], 'w') as foutput:
        for line in blocked_domains:
            foutput.write(f'{line}\n')

    # remove duplicates
    with open(config['raw_parsed_file']) as f:
        seen = set()
        duplicates = []
        for line in f:
            if line in seen:
                duplicates.append(line)
            else:
                seen.add(line)

    with open(config['raw_parsed_file'], 'r') as file_input:
        blocked_domains_file = config['blocked_domains_file']
        with open(blocked_domains_file, 'w') as output_file:
            for line in file_input:
                if line in duplicates:
                    continue
                output_file.write(line)
    logger.debug(f"Written to file: {blocked_domains_file}")


def update_blocked_domains():
    source = config['blocked_domains_file']
    destination = config['blocked_domains_target_path']
    try:
        shutil.copy(source, destination)
        logger.debug(f"Updated blocked domains file at {destination}")

        os.system("rndc reload")
        logger.debug("Reloaded bind process using rndc")
    except Exception as ex:
        logger.error(f"An error occured when copying the {source} to {destination}. Exception {ex}")


for item in ['./old_hosts', './new_hosts', config['raw_parsed_file']]:
    logger.debug('Cleaning up...')
    try:
        os.remove(item)
    except FileNotFoundError:
        logger.warning(f'File {item} not found')


if __name__ == '__main__':
    create_domain_list_file()
    while True:
        if has_diff() or has_new_additional_domains():
            logger.debug('A diff has been found!')
            process_new_hosts()
            update_blocked_domains()
            time.sleep(config['wait_time'])
        else:
            logger.debug('No diff found, continuing...')
            time.sleep(config['wait_time'])

            logger.debug('Renaming new_hosts')
            os.rename(config['fresh_blacklist_file'], config['stale_blacklist_file'])
            logger.debug('Downloading from source')
            create_domain_list_file()
