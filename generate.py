import requests
import os
from additional_domains import additional_domains


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
    if " " in line:
        line = line[0:line.index(" ")]
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
        print(f'Appended {entry}')
        new_lines.append(entry)
    return new_lines


def process_additional_domains_list(data):
    new_lines = []
    for line in data:
        new_lines.append(apply_bind_format(line))
    return new_lines


print('Processing')
blocked_domains_file = 'named.conf.blockeddomains'
url = 'https://www.someonewhocares.org/hosts/hosts'
# url = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'

r = requests.get(url, stream=True)
with open('hosts', 'wb') as hosts:
    for chunk in r.iter_content(chunk_size=80):
        if chunk:
            hosts.write(chunk)

with open('hosts', 'r') as raw:
    data = raw.read().splitlines(True)

blocked_domains = process_blocked_domains_list(data) + process_additional_domains_list(additional_domains)

with open('raw_parsed_as_bind_file', 'w') as foutput:
    for line in blocked_domains:
        foutput.write(f'{line}\n')

# remove duplicates
with open('raw_parsed_as_bind_file') as f:
    seen = set()
    duplicates = []
    for line in f:
        if line in seen:
            duplicates.append(line)
        else:
            seen.add(line)

with open('raw_parsed_as_bind_file', 'r') as file_input:
    with open(blocked_domains_file, 'w') as output_file:
        for line in file_input:
            if line in duplicates:
                continue
            output_file.write(line)
print(f'Written to file: {blocked_domains_file}')

os.remove('hosts')
os.remove('raw_parsed_as_bind_file')
print('Removed source files\nAll done!')
