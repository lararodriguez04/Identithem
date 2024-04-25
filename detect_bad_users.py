"""

Test to detect bad users using .xml files

"""

import xml.etree.ElementTree as ET
import re
import os

def parse_xml_rules(xml_file):
    """
    Gets an xml file and extracts the rules in a list
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    rules = []
    for rule in root.findall('rules'):
        urls = [url.text.strip() for url in rule.findall('url')]
        regex = [reg.text.strip() for reg in rule.findall("regex")]
        # Regexp in Apache_rules are not well written
        if len(regex) != 0:
            for i, reg in enumerate(regex):
                if reg[0]=="[" and reg[-1]=="]":
                    regex[i] = reg[1:len(reg)-1]
                
        """
        Add more characteristics if needed
        """
        description = rule.find('description').text.strip()
        rules.append((urls, regex, description))
    print(rules)
    return rules

def check_malicious(log_line, rules):
    """
    Checks if a log line can be classfied as malicious or not
    """
    urls, regex, description = rules[0], rules[1], rules[2]
    if len(urls) != 0:
        for url in urls:
            if url in log_line:
                return True, description
    elif len(regex) != 0:
        for reg in regex:
            if re.search(reg, log_line):
                return True, description
        """
        Check other characteristics
        """
    return False, None

def main():
    # Store malicious users and non-malicious
    malicious_logs = []
    good_logs = []

    # Parse XML files containing rules
    web_rules = parse_xml_rules('rules/0245-web_rules.xml')
    apache_rules = parse_xml_rules('rules/0250-apache_rules.xml')
    #web_accesslog_decoders = parse_xml_rules('rules/0375-web-accesslog_decoders.xml')
    
    # Combine all rules
    all_rules = web_rules + apache_rules
    
    # Read and process log file
    directory = "logs/"
    for file in os.listdir(directory):
        filename = directory+file
        with open(filename, 'r') as file:
            for num, line in enumerate(file):
                is_malicious = False
                for rules in all_rules:
                    rule_matched, description = check_malicious(line, rules)
                    if rule_matched:
                        is_malicious = True
                        break
                if is_malicious:
                    malicious_logs.append((f"Log {num}", description))
                else:
                    good_logs.append(f"Log {num}")
    
        print(f"Number of malicious logs in file {filename}: ", len(malicious_logs))
        print(f"Number of good logs in file {filename}: ", len(good_logs))
    
    return malicious_logs, good_logs


if __name__ == "__main__":
    malicious_logs, good_logs = main()


