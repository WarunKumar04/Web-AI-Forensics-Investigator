import re


def parse_log_for_sql_injection(log_line):
    sql_injections = []
    
    patterns = [
        r"union.*select.*from",
        r"select.*from.*information_schema.tables",
        r"select.*from.*mysql.db",
        r"select.*from.*users",
        r"drop.*table.*",
        r"select.*group_concat.*from",
        r"and.*1=1",
        r"or.*1=1"
    ]
    if any(re.search(pattern, log_line, re.IGNORECASE) for pattern in patterns):
        sql_injections.append(log_line)
    return sql_injections


def parse_log_for_xss(log_line):
    xss_payloads = [
        '<script>', 'alert(', 'onerror=', 'javascript:',
        'document.cookie', 'eval(', 'window.location',
        '<img src=x onerror=', '<iframe', '<object',
        '<embed', '<svg', '<math', '<audio', '<video'
    ]
    xss_attempts = []
    if any(payload in log_line for payload in xss_payloads):
        xss_attempts.append(log_line)
    return xss_attempts


def parse_log_for_csrf(log_line):
    csrf_patterns = [
        r"POST\s.*\sHTTP/1\.1",   
        r"csrf_token",            
        r"anti-forgery",           
        r"window.location",       
        r"submit.*button"          
    ]
    csrf_attempts = []
    if any(re.search(pattern, log_line, re.IGNORECASE) for pattern in csrf_patterns):
        csrf_attempts.append(log_line)
    return csrf_attempts


def parse_log_for_rfi_lfi(log_line):
    rfi_lfi_patterns = [
        r"\.\./",                  
        r"php://input",            
        r"file://",               
        r"include",               
        r"require",               
        r"eval",                   
        r"exec"                    
    ]
    rfi_lfi_attempts = []
    if any(re.search(pattern, log_line, re.IGNORECASE) for pattern in rfi_lfi_patterns):
        rfi_lfi_attempts.append(log_line)
    return rfi_lfi_attempts


def parse_log_for_command_injection(log_line):
    command_injections = []
   
    patterns = [
        r"\;.*\s",                 
        r"\&\&.*\s",               
        r"\|\|.*\s",               
        r"\`.*\`",                 
        r"system\(",              
        r"exec\(",                
        r"shell_exec\("
    ]
    if any(re.search(pattern, log_line, re.IGNORECASE) for pattern in patterns):
        command_injections.append(log_line)
    return command_injections


def parse_log_for_path_traversal(log_line):
    path_traversals = []
   
    if re.search(r"\.\./", log_line):
        path_traversals.append(log_line)
    return path_traversals
