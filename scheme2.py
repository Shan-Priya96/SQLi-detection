import re

def is_sql_injection(input_str):
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "WHERE", "OR", "AND", "FROM"]
    sql_symbols = ["=", "'", "\"", ";", "--", "/*", "*/"]
    
    # Remove leading spaces
    input_str = input_str.lstrip()

    # Check if the first non-space character is a quote
    if input_str and input_str[0] in ["'", "\""]:
        return True
    
    pattern = "|".join(map(re.escape, sql_keywords + sql_symbols))
    matches = re.findall(pattern, input_str, re.IGNORECASE)
    return len(matches) > 0

user_input = input("Enter a value: ")

if is_sql_injection(user_input):
    print("Potential SQL injection detected.")
else:
    print("Input seems safe.")