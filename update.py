import requests
import os

prefix = 'zone "'
suffix = '" {type master; file "named.empty";};'

def apply_format(line):
    return f'{prefix}{line}{suffix}'

def parse_blocked_domain(line):
    line = line[11:]
    line = line.replace("\n", "")
    return apply_format(line)

def process_blocked_domains_list(data):
    new_lines = []
    for line in data:
        new_lines.append(parse_blocked_domain(line))
    return new_lines

def process_additional_domains_list(data):
    new_lines = []
    for line in data:
        new_lines.append(apply_format(line))
    return new_lines

url = 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
file_name = './hosts.txt'
myfile = requests.get(url)

open(file_name, 'wb').write(myfile.content)

# remove first lines up to local host entry
with open(file_name, 'r') as finput:
    data = finput.read().splitlines(True)
with open(file_name, 'w') as foutput:
    foutput.writelines(data[6:])
        
with open(file_name, 'r') as finput:
    data = finput.read().splitlines(True)

# this is a personizable additional_domains.py file that is added to .gitignore
from additional_domains import additional_domains
blocked_domains = process_blocked_domains_list(data) + process_additional_domains_list(additional_domains)

new_file_name = './named.conf.blockeddomains' 
with open(new_file_name, 'w') as foutput:
    for line in blocked_domains:
        foutput.write(f'{line}\n')

print(f'Written to file: {new_file_name}')
os.remove(file_name)
print('Removed source file\nAll done!')
