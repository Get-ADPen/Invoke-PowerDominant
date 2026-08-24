#!/usr/bin/env python3
import sys, re, os, random, string

def rand_name(lo=6, hi=14):
    n = random.randint(lo, hi)
    return random.choice(string.ascii_letters) + ''.join(
        random.choices(string.ascii_letters + string.digits, k=n - 1)
    )

PS_PROTECTED = {
    '_','args','true','false','null','this','input','error',
    'pid','pwd','psscriptroot','pscommandpath','psboundparameters',
    'psversiontable','myinvocation','executioncontext','host','profile',
    'matches','ofs','outputencoding','home','islinux','iswindows',
    'ismacOS','lastexitcode','foreach','switch','psdefaultparametervalues',
    'erroractionpreference','warningpreference','verbosepreference',
    'debugpreference','informationpreference','progresspreference',
    'confirmpreference','whatifpreference','env','psitem','pscmdlet',
    'psedition','nestedpromptlevel','shellid','consolefilename',
    'psuiculture','psculture'
}

FLAGGED_FRAGS = [
    'AmsiScanBuffer','AmsiInitialize','AmsiOpenSession','amsi.dll',
    'amsiContext','amsiSession',
    'System.Net.Sockets','System.Net.WebClient','Net.WebClient',
    'System.Management.Automation',
    'VirtualAlloc','VirtualProtect','CreateThread',
    'WriteProcessMemory','OpenProcess','LoadLibrary',
    'sekurlsa','mimikatz','wdigest',
    'WScript.Shell','Shell.Application',
    'kernel32','ntdll','msvcrt',
    'Invoke-Mimikatz','Invoke-Shellcode',
    'Invoke-ReflectivePEInjection','Get-GPPPassword',
]

CMDLETS = [
    'New-Object','Get-Item','Get-ChildItem','Set-Item','Remove-Item',
    'Invoke-Expression','Invoke-Command','Out-String','Write-Host',
    'Write-Output','Get-Content','Set-Content','Add-Content',
    'Select-Object','Where-Object','ForEach-Object','Sort-Object',
    'Group-Object','Format-Table','Format-List',
    'Get-Process','Stop-Process','Start-Process',
    'Get-Service','Start-Service','Stop-Service',
    'Get-WmiObject','Get-CimInstance',
    'Get-ItemProperty','Set-ItemProperty',
    'Get-Acl','Set-Acl','Add-Type','Get-Random','Start-Sleep',
    'ConvertTo-Json','ConvertFrom-Json',
    'ConvertTo-SecureString','ConvertFrom-SecureString',
    'Import-Module','Test-Path','Join-Path','Split-Path','Resolve-Path',
    'Get-ScheduledTask','Get-Date',
]

BACKTICK_TARGETS = [
    'New-Object','Invoke-Expression','Add-Type','Get-WmiObject',
    'Get-CimInstance','Start-Process','Invoke-Command',
    'DownloadString','DownloadFile',
]

def get_single_quoted_positions(code):
    positions = set()
    i = 0
    n = len(code)
    while i < n:
        if code[i] == '@' and i + 1 < n and code[i+1] == "'":
            end = code.find("'@", i + 2)
            if end == -1: break
            for j in range(i, end + 2): positions.add(j)
            i = end + 2
            continue
        if code[i] == "'":
            j = i + 1
            while j < n:
                if code[j] == "'" and (j + 1 >= n or code[j+1] != "'"):
                    break
                if code[j] == "'":
                    j += 2
                    continue
                j += 1
            for k in range(i, min(j + 1, n)):
                positions.add(k)
            i = j + 1
            continue
        i += 1
    return positions

def strip_line_comment(line):
    in_sq = in_dq = False
    for i, c in enumerate(line):
        if c == "'" and not in_dq: in_sq = not in_sq
        elif c == '"' and not in_sq: in_dq = not in_dq
        elif c == '#' and not in_sq and not in_dq:
            return line[:i].rstrip()
    return line

def strip_comments(code):
    code = re.sub(r'<#.*?#>', ' ', code, flags=re.DOTALL)
    return '\n'.join(strip_line_comment(l) for l in code.split('\n'))

def rename_variables(code):
    pattern = re.compile(r'\$([A-Za-z][A-Za-z0-9_]*)', re.IGNORECASE)
    sq = get_single_quoted_positions(code)

    all_vars = set()
    for m in pattern.finditer(code):
        if m.start() not in sq:
            key = m.group(1).lower()
            if key not in PS_PROTECTED:
                all_vars.add(key)

    used = set(PS_PROTECTED)
    mapping = {}
    for var in sorted(all_vars):
        new = rand_name()
        while new.lower() in used:
            new = rand_name()
        used.add(new.lower())
        mapping[var] = new

    def replacer(m):
        if m.start() in sq:
            return m.group(0)
        key = m.group(1).lower()
        return '$' + mapping[key] if key in mapping else m.group(0)

    return pattern.sub(replacer, code), mapping

def rename_functions(code):
    fn_pat = re.compile(r'\bfunction\s+([A-Za-z][A-Za-z0-9_\-]*)\b', re.IGNORECASE)
    fn_names = set(m.group(1) for m in fn_pat.finditer(code))

    used = set()
    mapping = {}
    for fn in sorted(fn_names, key=len, reverse=True):
        new = rand_name()
        while new in used:
            new = rand_name()
        used.add(new)
        mapping[fn] = new

    for old, new in sorted(mapping.items(), key=lambda x: len(x[0]), reverse=True):
        code = re.sub(
            r'(?i)\bfunction\s+' + re.escape(old) + r'\b',
            f'function {new}', code
        )
        code = re.sub(
            r'(?<![A-Za-z0-9_\-])' + re.escape(old) + r'(?![A-Za-z0-9_\-])',
            new, code, flags=re.IGNORECASE
        )

    return code, mapping

def split_flagged_strings(code):
    for frag in sorted(FLAGGED_FRAGS, key=len, reverse=True):
        if len(frag) < 5:
            continue
        mid = random.randint(max(1, len(frag)//3), max(2, 2*len(frag)//3))
        p1, p2 = frag[:mid], frag[mid:]
        code = code.replace(f"'{frag}'", f"('{p1}'+'{p2}')")
        code = code.replace(f'"{frag}"', f'("{p1}"+"{p2}")')
    return code

def randomize_cmdlet_case(code):
    sq = get_single_quoted_positions(code)
    for cmdlet in sorted(CMDLETS, key=len, reverse=True):
        pat = re.compile(
            r'(?<![A-Za-z0-9_\-])' + re.escape(cmdlet) + r'(?![A-Za-z0-9_\-])',
            re.IGNORECASE
        )
        result = []
        last = 0
        for m in pat.finditer(code):
            result.append(code[last:m.start()])
            if m.start() not in sq:
                result.append(''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in m.group(0)
                ))
            else:
                result.append(m.group(0))
            last = m.end()
        result.append(code[last:])
        code = ''.join(result)
    return code

def insert_backticks(code):
    sq = get_single_quoted_positions(code)
    for target in sorted(BACKTICK_TARGETS, key=len, reverse=True):
        pat = re.compile(re.escape(target), re.IGNORECASE)
        result = []
        last = 0
        for m in pat.finditer(code):
            result.append(code[last:m.start()])
            if m.start() not in sq:
                word = m.group(0)
                safe_positions = [
                    i for i in range(1, len(word))
                    if word[i] != '-' and word[i-1] != '-'
                ]
                if safe_positions:
                    pos = random.choice(safe_positions)
                    word = word[:pos] + '`' + word[pos:]
                result.append(word)
            else:
                result.append(m.group(0))
            last = m.end()
        result.append(code[last:])
        code = ''.join(result)
    return code

def remove_blank_lines(code):
    lines = [l for l in code.split('\n') if l.strip()]
    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print('Usage: python3 python_to_power.py <script.ps1>')
        sys.exit(1)

    infile = sys.argv[1]
    if not os.path.exists(infile):
        print(f'[-] Not found: {infile}')
        sys.exit(1)

    base, ext = os.path.splitext(os.path.basename(infile))
    outdir  = os.path.dirname(os.path.abspath(infile))
    outfile = os.path.join(outdir, f'{base}_pychanged{ext}')

    with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()

    orig_size = len(code)

    code = strip_comments(code)
    code, var_map  = rename_variables(code)
    code, fn_map   = rename_functions(code)
    code = split_flagged_strings(code)
    code = randomize_cmdlet_case(code)
    code = insert_backticks(code)
    code = remove_blank_lines(code)

    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(code)

    print(f'[+] Input    : {infile} ({orig_size} bytes)')
    print(f'[+] Output   : {outfile} ({len(code)} bytes)')
    print(f'[+] Vars     : {len(var_map)} renamed')
    print(f'[+] Functions: {len(fn_map)} renamed')

    if var_map:
        print('\n[*] Variable map (first 10):')
        for old, new in list(var_map.items())[:10]:
            print(f'    ${old} -> ${new}')
    if fn_map:
        print('\n[*] Function map:')
        for old, new in fn_map.items():
            print(f'    {old} -> {new}')

if __name__ == '__main__':
    main()