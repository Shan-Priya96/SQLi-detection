import re
def contains_urls_or_ip_addresses(text):
    return bool(re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
print(contains_urls_or_ip_addresses(input()))