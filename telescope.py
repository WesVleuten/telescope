#!/usr/bin/env python3

import getopt, sys, os, time, _thread, threading, subprocess, datetime, base64
import xml.etree.ElementTree as ET

show_banner = True
target = 0
depth = 1
no_ping = False
output_dir = 'telescope'
wordlist = '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
extensions = ',php,html,txt,md,sh,py'

helptext = ("""
Telescope: Auto recon tool

This tool depends on gobuster and nmap.

Flags:
    -h, --help\t\t\tShows this help
    -t, --target IP\t\tTarget ip address
    -P, --no-ping\t\tSkips ping check on all nmap scans
    -b, --no-banner\t\tSkips showing the telescope banner
        --verbosity LEVEL\t\tSets the verbosity 0-5

Gobuster
        --gb-wordlist FILE\t\tSets gobuster wordlist, defaults to "%s"
""" % (wordlist)).strip()

full_cmd_arguments = sys.argv
argument_list = full_cmd_arguments[1:]

short_options = "ht:o:vP"
long_options = ["help", "target=", "output=", "verbose", "no-ping", "verbosity=", "gb-wordlist="]
verbosity = 0

threads = []

def vprint(v, service, input):
    if v <= verbosity:
        date = datetime.datetime.now().replace(microsecond=0).isoformat()
        print('[%s] %s >> %s' % (date, service, input))

def question(service, msg, options=['y','n']):
    date = datetime.datetime.now().replace(microsecond=0).isoformat()
    result = 'thisisdefinitlynotanoption'
    while result.lower() not in options:
        result = input('[%s] %s >> %s [%s]: ' % (date, service, msg, '/'.join(options)))
    return result

class MThread(threading.Thread):
    def __init__(self, func, arg):
        threading.Thread.__init__(self)
        self.function = func
        self.arguments = arg
    def run(self):
        self.function(**self.arguments)

def run_simple_cmd(cmdstr):
    vprint(4, "TELESC", "Running command \"%s\"" % cmdstr)
    return os.popen(cmdstr).read()

def host_up(recursive_level=0):
    if target == 0:
        vprint(0, "TELESC", "Invalid target (%s)" % target)
        return False
    if recursive_level > 10:
        vprint(0, "TELESC", "Tried 10 times, no result, check if host is up or if it reponds to pings.")
        return False
    if no_ping:
        return True
    r = run_simple_cmd(("nmap -T5 --max-retries=3 -sn %s") % target)
    result = "1 host up" in r
    if result:
        vprint(1, "TELESC", "Host is up")
    else:
        vprint(0, "TELESC", "Host is not up, does it respond to pings? Retrying in 5s")
        time.sleep(5)
        return host_up(recursive_level+1)
    return result
    
def parse_arugments():
    global target, verbosity, no_ping, depth, wordlist
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    for current_argument, current_value in arguments:
        if current_argument in ("--verbosity"):
            verbosity = int(current_value)
            vprint(3, "TELESC", ("Setting verbosity to %s") % (verbosity))
        elif current_argument in ("-h", "--help"):
            print(helptext)
            sys.exit(1)
        elif current_argument in ("-o", "--output"):
            vprint(3, "TELESC", ("Enabling special output mode (%s)") % (current_value))
        elif current_argument in ("-t", "--target"):
            target = current_value
            vprint(3, "TELESC", ("Setting target to %s") % (target))
        elif current_argument in ("-d", "--depth"):
            vprint(3, "TELESC", ("Setting gobuster depth to %s") % (current_value))
            depth = current_value
        elif current_argument in ("--gb-wordlist"):
            vprint(3, "TELESC", ("Setting gobuster wordlist to %s") % (current_value))
            wordlist = current_value
        elif current_argument in ("-P", "--no-ping"):
            vprint(3, "TELESC", "Setting no_ping to True")
            no_ping = True
        elif current_argument in ("-b", "--no-banner"):
            vprint(3, "TELESC", "Setting show_banner to False")
            show_banner = False

def create_result_dir():
    global output_dir
    original_dir = output_dir
    i = 1
    while os.path.isdir(output_dir):
        output_dir = original_dir + "." + str(i)
        i += 1
    os.mkdir(output_dir)
    vprint(2, "TELESC", "Set output directory to %s" % output_dir)

def getopenports():
    ports = []
    root = ET.parse('%s/nmap-quickscan.xml' % output_dir).getroot()
    for port in root.findall('./host/ports/port'):
        ports.append(port.attrib['portid'])
    return ports

def getwebports():
    webs = []
    root = ET.parse('%s/nmap-quickscan.xml' % output_dir).getroot()
    for port in root.findall('./host/ports/port'):
        portid = port.attrib['portid']
        service = port.findall('./service')[0].attrib['name']
        if service == 'http-proxy': service = 'http'
        if service == 'https-proxy': service = 'https'
        if service in ['http', 'https']:
            webs.append({
                'protocol': service,
                'portid': portid
            })
    return webs

def gobuster(protocol='http', targetport=80, targeturi=''):
    do_recursive = 0

    url = "%s://%s:%s/%s" % (protocol, target, targetport, targeturi)
    filename = 'root'
    if targeturi != '':
        filename = targeturi.replace('/', '-')
    cmd = "gobuster dir -qfazk -t 5 --timeout 5s -x %s -o %s/gobuster-%s.txt -u \"%s\" -w %s" % (extensions, output_dir, filename, url, wordlist)
    vprint(0, "GOBUST", "Staring %s" % url)

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip().decode("utf-8")
        if not line:
            break
        # print(len(line), line[0], line)
        vprint(0, "GOBUST", "%s%s" % (url, line[1:]))
        
        if len(line) > 10:
            uri = str.split(line, ' (Status:')[0]
            if uri[-1] == '/':
                p = ''
                if (do_recursive == 0):
                    p = question('GOBUST', 'Want to scan "%s%s"?' % (url, uri[1:]), ['y', 'n', 'always', 'never'])
                if (p == 'always'): do_recursive = 1
                if (p == 'never'): do_recursive = -1
                if (do_recursive == 1): p = 'y'
                if (p == 'y'):
                    t = MThread(gobuster, { 'protocol': protocol, 'targetport': targetport, 'targeturi': uri[1:] })
                    threads.append(t)
                    t.start()

def main():
    global threads
    try:
        if os.geteuid() != 0:
            vprint(0, "TELESC", "Some scans require root privileges, please run as root")
            return
            
        parse_arugments()

        if show_banner:
            print(base64.b64decode("ICBfX19fX19fICAgXyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiB8X18gICBfX3wgfCB8ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgfCB8IF9fX3wgfCBfX18gIF9fXyAgX19fIF9fXyAgXyBfXyAgIF9fXyAKICAgIHwgfC8gXyBcIHwvIF8gXC8gX198LyBfXy8gXyBcfCAnXyBcIC8gXyBcCiAgICB8IHwgIF9fLyB8ICBfXy9cX18gXCAoX3wgKF8pIHwgfF8pIHwgIF9fLwogICAgfF98XF9fX3xffFxfX198fF9fXy9cX19fXF9fXy98IC5fXy8gXF9fX3wKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfCB8ICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHxffCAgICAgICAgIHZBTFBIQQo=").decode("utf-8"))
        
        vprint(0, "TELESC", "Checking if host is alive...")

        if host_up() == False:
            return

        vprint(0, "TELESC", "Starting initial scan...")
        
        create_result_dir()
        quickscan = run_simple_cmd("nmap -Pn -sS -p- -T5 --min-rate 2500 --max-retries 3 -oN %s/nmap-quickscan.nmap -oX %s/nmap-quickscan.xml %s" % (output_dir, output_dir, target))
        
        vprint(0, "TELESC", "Starting in depth scan...")

        ports = ','.join(str(x) for x in getopenports())
        fullscan = run_simple_cmd("nmap -Pn -O -sV -sC -p%s -T5 --min-rate 2500 --max-retries 3 -oN %s/nmap-fullscan.nmap -oX %s/nmap-fullscan.xml %s" % (ports, output_dir, output_dir, target))
        
        vprint(0, "TELESC", "Starting services scan...")

        for web in getwebports():
            q = question('TELESC', 'Found a webserive using %s on %s, scan with gobuster?' % (web['protocol'], web['portid']))
            if (q == 'n'):
                continue
            try:
                t = MThread(gobuster, { 'protocol': web['protocol'], 'targetport': web['portid'] })
                threads.append(t)
                t.start()
            except:
                print("Error: unable to start gobuster thread")
        
        while any( t.is_alive() for t in threads ):
            pass
    except KeyboardInterrupt:
        vprint(1, "TELESC", "Goodbye")

if __name__ == "__main__":
    main()