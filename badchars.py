#!/usr/bin/python

import re
import sys
import string
import os.path
from optparse import OptionParser
from collections import defaultdict

options = {}
filenames = []
buffers = [[], []]

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def _out(x, color=None):
    if not options.quiet:
        if color and options.colored: return color + x + bcolors.ENDC
        else: return x 
    else: return "" 

def out(x): 
    o = _out(x)
    if len(o): print o
        
def ok(x): return _out("[+] " + x, bcolors.OKGREEN)
def dbg(x): 
    if options.debug:
        return _out("[dbg] " + x, bcolors.OKBLUE)
    else:
        return ''

def warn(x): return _out("[?] " + x, bcolors.WARNING)
def err(x): return _out(x, bcolors.FAIL)

class BytesParser():
    formats_rex = {
        'xxd': r'^[^0-9a-f]*[0-9a-f]{2,}\:\s((?:[0-9a-f]{4}\s)+)\s+.+$',
        'hexdump': r'^[^0-9a-f]*[0-9a-f]{2,}\s+([0-9a-f\s]+[0-9a-f])$',
        'classic-hexdump':r'^[0-9a-f]*[0-9a-f]{2,}(?:\:|\s)+\s([0-9a-f\s]+)\s{2,}.+$',
        'hexdump-C': r'^[0-9a-f]*[0-9a-f]{2,}\s+\s([0-9a-f\s]+)\s*\|', 
        'escaped-hexes': r'^[^\'"]*((?:\'[\\\\x0-9a-f]{8,}\')|(?:"[\\\\x0-9a-f]{8,}"))',
        'hexstring': r'^([0-9a-f]+)$',
        'powershell': r'^[^0x]+((?:0x[0-9a-f]{1,2},?)+)$',
        'byte-array': r'^[^0x]*((?:0x[0-9a-f]{2}(?:,\s?))+)',
        'js-unicode': r'^[^%u0-9a-f]*((?:%u[0-9a-f]{4})+)$',
        'dword': r'^(?:(?:0x[0-9a-f]{1,8}\s[<>\w\+]+):\s)?((?:0x[0-9a-f]{8},?\s*)+)$',
    }
    formats_aliases = {
        'classic-hexdump': ['ollydbg'],
        'escaped-hexes': ['ruby','c', 'carray', 'python'],
        'dword': ['gdb']
    }
    formats_compiled = {}

    def __init__(self, input, name = None, format = None):
        self.input = input[:]
        self.name = name
        self.bytes = []
        self.parsed = False
        self.format = None

        BytesParser.compile_regexps()

        self.normalize_input()

        if format:
            print dbg("Using user-specified format: %s" % format)
            assert format in BytesParser.formats_rex.keys(), \
                    "Format '%s' is not implemented." % format
            self.format = format
        else:
            self.recognize_format()

        if not self.format:
            self.parsed = False
        else:
            if self.fetch_bytes():
                out(ok("Fetched %d bytes successfully from %s" % (len(self.bytes), self.name)))
                self.parsed = True
            else:
                if format and len(format):
                    out(err("Could not parse %s with user-specified format: %s" % (self.name, format)))
                else:
                    out(err("Recognized input %s as formatted with %s but failed fetching bytes." %
                        (self.name, self.format)))

    def normalize_input(self):
        input = []
        for line in self.input.split('\n'):
            line = line.strip()
            line2 = line.encode('string-escape')
            input.append(line2)
        self.input = '\n'.join(input)

    @staticmethod
    def interpret_format_name(name):
        for k, v in BytesParser.formats_aliases:
            if name.lower() in v:
                return k
        raise Exception("Format name: %s not recognized as alias." % name)

    @staticmethod
    def compile_regexps():
        if len(BytesParser.formats_compiled) == 0:
            for name, rex in BytesParser.formats_rex.items():
                BytesParser.formats_compiled[name] = re.compile(rex, re.I)

    @staticmethod
    def make_line_printable(line):
        return ''.join([c if c in string.printable else '.' for c in line])

    def recognize_format(self):
        for line in self.input.split('\n'):
            if self.format: break
            for format, rex in BytesParser.formats_compiled.items():
                line = BytesParser.make_line_printable(line)

                out(dbg("Trying format %s on ('%s')" % (format, line)))
                
                if rex.match(line):
                    out(ok("%s has been recognized as %s formatted." % (self.name, format)))
                    self.format = format
                    break

        if not self.format:
            if not all(c in string.printable for c in self.input):
                out(ok("%s has been recognized as RAW bytes." % (self.name)))
                self.format = 'raw'
                return True
            else:
                out(err("Could not recognize input bytes format of the %s!" % self.name))
                return False

        return (len(self.format) > 0)

    @staticmethod
    def post_process_bytes_line(line):
        outb = []
        l = line.strip()[:]
        strip = ['0x', ',', ' ', '\\', 'x', '%u', '+', '.', "'", '"']
        for s in strip:
            l = l.replace(s, '')

        for i in xrange(0, len(l), 2):
            outb.append(int(l[i:i+2], 16))
        return outb

    @staticmethod
    def preprocess_bytes_line(line):
        l = line.strip()[:]
        strip = ['(byte)', '+', '.']
        for s in strip:
            l = l.replace(s, '')
        return l

    @staticmethod
    def unpack_dword(line):
        outs = ''
        i = 0
        for m in re.finditer(r'((?:0x[0-9a-f]{8},?\s*))', line):
            l = m.group(0)
            l = l.replace(',', '')
            l = l.replace(' ', '')
            dword = int(l, 16)
            unpack = reversed([
                (dword & 0xff000000) >> 24,
                (dword & 0x00ff0000) >> 16,
                (dword & 0x0000ff00) >>  8,
                (dword & 0x000000ff)
            ])
            i += 4
            for b in unpack:
                outs += '%02x' % b

        out(dbg("After callback ('%s')" % outs))
        return BytesParser.formats_compiled['hexstring'].match(outs)

    def fetch_bytes(self):
        if not self.format:
            out(err("fetch_bytes(): Format has not been specified!"))
            return False

        if self.format == 'raw':
            out(dbg("Parsing %s as raw bytes." % self.name))
            self.bytes = [ord(c) for c in list(self.input)]
            return len(self.bytes) > 0
        
        for line in self.input.split('\n'):
            callback_called = False
            if self.format in BytesParser.formats_callbacks.keys() and \
                    BytesParser.formats_callbacks[self.format]:
                out(dbg("Before callback ('%s')" % line))
                m = BytesParser.formats_callbacks[self.format].__func__(line)
                callback_called = True
            else:
                line = BytesParser.preprocess_bytes_line(line[:])
                m = BytesParser.formats_compiled[self.format].match(line)

            if m:
                extract = ''
                for mg in m.groups()[0:]:
                    if len(mg) > 0:
                        extract = mg
                bytes = BytesParser.post_process_bytes_line(extract)
                if not bytes:
                    out(err("Could not process %s bytes line ('%s') as %s formatted! Quitting." \
                            % (self.name, line, self.format)))
                else:
                    out(dbg("Line ('%s'), bytes ('%s'), extracted ('%s'), len: %d" % (line, extract, bytes, len(bytes))))
                    self.bytes.extend(bytes)
            else:
                if callback_called:
                    out(dbg("Callback failure: transformed string ('%s') did not catched on returned match" % (line)))
                else:
                    out(dbg("Parsing line ('%s') failed with format '%s'." % (line, self.format)))

        return len(self.bytes) > 0

    def get_bytes(self):
        return self.bytes

    formats_callbacks = {
        'dword': unpack_dword
    }

class HexDumpPrinter:
    def __init__(self, options, good_buffer, bad_buffer):
        self.dump1 = HexDumpPrinter.hex_dump(buffers[0]).split('\n')
        self.dump2 = HexDumpPrinter.hex_dump(buffers[1]).split('\n')
        self.minlen = min(len(self.dump1), len(self.dump2))

        self.bad_start_diff = bcolors.FAIL
        self.bad_stop_diff = bcolors.ENDC

        self.good_start_diff = bcolors.OKGREEN
        self.good_stop_diff = bcolors.ENDC

        self.address_good = '+'
        self.address_bad = '-'

        if not options.colored:
            self.good_start_diff = '-'
            self.good_stop_diff = '-'
            self.bad_start_diff = '!'
            self.bad_stop_diff = '!'
        else:
            self.address_good = bcolors.OKGREEN + self.address_good + bcolors.ENDC
            self.address_bad = bcolors.FAIL + self.address_bad + bcolors.ENDC

    @staticmethod
    def hex_dump(data):
        s = ''
        n = 0
        lines = []

        def val(x):
            if type(x) == type(0): return x
            elif type(x) == type(''): return ord(x)
            elif type(x) == type([]): return _val(x[0])
            raise Exception("Unknown type of single byte.")

        if len(data) == 0:
            return '<empty>'

        for i in range(0, len(data), 16):
            line = ''
            line += '%04x | ' % (i)
            n += 16

            for j in range(n-16, n):
                if j >= len(data): break
                line += '%02x ' % val(data[j])

            line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

            for j in range(n-16, n):
                if j >= len(data): break
                c = data[j] if not (val(data[j]) < 0x20 or val(data[j]) > 0x7e) else '.'
                line += '%c' % c

            lines.append(line)

        return '\n'.join(lines)

    @staticmethod
    def wide_line(letter, d1, d2):
        d1t = d1.split(' | ')
        d2t = d2.split(' | ')

        if options.colored:
            letter = bcolors.HEADER + letter + bcolors.ENDC

        return '{}{} | {} | {} | {}  | {}'.format(letter, d1t[0], d1t[1], d1t[2], d2t[1], d2t[2])

    @staticmethod
    def extract_bytes(line):
        linet = line.split(' | ')
        strbytes = linet[1].strip().split(' ')
        bytes = []
        for s in strbytes:
            bytes.append(s)
        return bytes

    @staticmethod
    def reconstruct_line(letter, line, bytes):
        bytes_line = ''
        linet = line.split(' | ')
        color_address = False

        diff_indexes = []
        i = 0
        for b in bytes:
            if len(b) != 2:
                # difference
                diff_indexes.append(i)
                color_address = True
                if len(b) == 4:
                    # not colored difference
                    l = list(bytes_line)
                    if len(l) > 1:
                        l[-1] = b[0]
                    bytes_line = ''.join(l)
                    bytes_line += b[1:]
                else:
                    # colored difference
                    bytes_line += b + ' '
            else:
                bytes_line += b + ' '
            i += 1

        address = linet[0]
        ascii = linet[2]

        for b in range(len(bytes), 16):
            bytes_line += ' ' * 3
            ascii += ' '

        if options.colored:
            new_ascii = ''
            for j in range(len(ascii)):
                if j in diff_indexes:
                    new_ascii += bcolors.FAIL + ascii[j] + bcolors.ENDC
                else:
                    new_ascii += ascii[j]
            new_ascii, ascii = ascii, new_ascii

        if color_address or len(letter) > 1:
            if options.colored:
                address = bcolors.OKBLUE + address + bcolors.ENDC
            else:
                address = address

        return '{}{} | {} | {}'.format(letter, address, bytes_line, ascii)

    def highlight_differences(self, d1, d2):
        if d1 != d2:
            d1t = d1.split(' | ')
            d2t = d2.split(' | ')

            d1bytes = HexDumpPrinter.extract_bytes(d1)
            d2bytes = HexDumpPrinter.extract_bytes(d2)
            minlen = min(len(d1bytes), len(d2bytes))

            for i in range(minlen):
                if d1bytes[i] != d2bytes[i]:
                    d1bytes[i] = self.good_start_diff + d1bytes[i] + self.good_stop_diff
                    d2bytes[i] = self.bad_start_diff + d2bytes[i] + self.bad_stop_diff

            if len(d1bytes) > minlen:
                for i in range(minlen, len(d1bytes)):
                    d1bytes[i] = self.good_start_diff + d1bytes[i] + self.good_stop_diff
            elif len(d2bytes) > minlen:
                for i in range(minlen, len(d2bytes)):
                    d2bytes[i] = self.bad_start_diff + d2bytes[i] + self.bad_stop_diff

            d1 = HexDumpPrinter.reconstruct_line(self.address_good, d1, d1bytes)
            d2 = HexDumpPrinter.reconstruct_line(self.address_bad, d2, d2bytes)
        
        return (d1, d2)
    
    def __str__(self):
        buff = ''
        for i in range(self.minlen):
            d1 = self.dump1[i].strip()
            d2 = self.dump2[i].strip()

            if d1 == d2:
                if not options.wide:
                    buff += ' ' + d1
                else:
                    buff += HexDumpPrinter.wide_line(' ', d1, d2)
            else:
                (d1, d2) = self.highlight_differences(d1, d2)
                if not options.wide:
                    buff += d1 + '\n' + d2
                else:
                    num = 1
                    if options.colored: num = 6
                    buff += HexDumpPrinter.wide_line('>', d1[num:], d2)

            buff += '\n'

        good_longer = len(self.dump1) > len(self.dump2)
        maxlen = max(len(self.dump1), len(self.dump2))
        once = False
        for i in range(self.minlen, maxlen):
            if (self.minlen + 8 < maxlen - 5) and i > self.minlen + 5 and i < maxlen - 5: 
                if not once: 
                    buff += ' ...' + '\n'
                    once = True
                continue
            if good_longer:
                buff += ' ' + self.dump1[i] + '\n'
            else:
                buff += ' ' + self.dump2[i] + '\n'

        return buff

def fetch_file(filename, name, format):
    out(dbg("Opening file '%s' as %s" % (filename, name)))
    with open(filename, 'rb') as f:
        buff = f.read()
        b = BytesParser(buff, name, format)
        if not b.parsed:
            sys.exit(1)
        else:
            return b.get_bytes() 

def parse_options():
    global options
    global filenames

    avail_formats = ['raw',]
    avail_formats.extend(BytesParser.formats_rex.keys())
    for k, v in BytesParser.formats_aliases.items():
        avail_formats.extend(v)

    formats = ', '.join(["'"+x+"'" for x in avail_formats])
    usage = "Usage: %prog [options] good_buffer bad_buffer\n\n"
    usage += "Buffers explanation:\n\t- good_buffer\t- file "
    usage += "containing buffer considered to be a model one, "
    usage += "having expected bytes in it.\n\t- bad_buffer\t- "
    usage += "file that has tainted/modified/varying bytes comparing to good_buffer."
    usage += "\n\nAvailable formats:\n\t" + formats

    parser = OptionParser(usage = usage)
    parser.add_option("-c", "--colored", action="store_true", dest="colored", default=False, 
                        help="Colors the comparison output.")
    parser.add_option("", "--format1", metavar="FORMAT", dest="format1", default=None, 
                        help="Enforce specific format on first buffer.")
    parser.add_option("", "--format2", metavar="FORMAT", dest="format2", default=None, 
                        help="Enforce specific format on second buffer.")
    parser.add_option("-w", "--wide", action="store_true", dest="wide", default=False, 
                        help="Wide mode, display hex dumps next to each other.")
    parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False, 
                        help="Debug mode - more verbose.")
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, 
                        help="Quiet mode, no infos. Return 1 if not equal, 0 otherwise.")

    (options, args) = parser.parse_args()
    if len(args) != 2:
        parser.error(err("You have to specify two buffer files."))
        parser.print_usage()
        return False

    if not os.path.isfile(args[0]):
        parser.error(err("First file specified does not exist."))
        parser.print_usage()
        return False

    if not os.path.isfile(args[1]):
        parser.error(err("Second file specified does not exist."))
        parser.print_usage()
        return False

    if options.format1: options.format1 = options.format1.lower()
    if options.format2: options.format2 = options.format2.lower()

    if options.format1 and options.format1 not in avail_formats:
        parser.error(err("Format1 that was specified is not recognized."))
        parser.error(err("Valid formats: %s" % formats))
        return False

    if options.format2 and options.format2 not in avail_formats:
        parser.error(err("Format2 that was specified is not recognized."))
        parser.error(err("Valid formats: %s" % formats))
        return False

    filenames = args

    return True

def check_if_match():
    diff = 0
    bad_chars = defaultdict(list)
    minlen = min(len(buffers[0]), len(buffers[1]))

    for i in xrange(minlen):
        if buffers[0][i] != buffers[1][i]:
            diff += 1
            bad_chars[buffers[0][i]].append(buffers[1][i])

    if len(buffers[0]) > minlen:
        bad_chars[-1].append(buffers[1][-1])
    elif len(buffers[1]) > minlen:
        bad_chars[-1].append(buffers[0][-1])

    return (diff, bad_chars)

def main(argv):
    if not parse_options():
        return 1

    buffers[0].extend(fetch_file(filenames[0], 'good_buffer', options.format1))
    buffers[1].extend(fetch_file(filenames[1], 'bad_buffer', options.format2))

    if len(buffers[0]) != len(buffers[1]):
        out("\n"+warn("Specified buffer files differ in contents length (%d, %d)!" \
                    % (len(buffers[0]), len(buffers[1]))))
    else:
        out(ok("Buffers are of same size: %d bytes." % len(buffers[0])))
        
    res, bad_chars = check_if_match()
    
    if not res:
        out(ok("\t\nBuffers match. No Bad characters found.\n"))
        return 0
    else:
        bad_chars_string = ''
        if not options.quiet:
            bad_chars_flatten = filter(lambda x: x != -1, bad_chars.keys())
            chars = ', '.join(['0x%02x' % c for c in bad_chars_flatten])
            bad_chars_string += _out("Likely to be bad chars: " + bcolors.HEADER + chars + "\n", bcolors.WARNING)
            bad_chars_string += _out("Found mappings:\n", bcolors.WARNING)

            tochar = lambda x: x if ((x > 0 and x < 256) and (chr(x) in string.printable)) else '.'
            added = set()
            for k, v in bad_chars.items():
                a = k
                a1 = tochar(k)
                for b in v:
                    b1 = tochar(b)
                    if (a, b) not in added and a != -1:
                        bad_chars_string += "\t0x%02x (%s) => 0x%02x (%s)\n" % (a, a1, b, b1)
                        added.add((a,b))

        minlen = min(len(buffers[0]), len(buffers[1]))
        proc = (float(res)/float(minlen) * 100.0)
        out(err("\n\tBuffers differ! Found at least %d differences (%d/%d, %0.2f%%) and %d bad chars\n" \
                % (res, res, minlen, proc, len(bad_chars_flatten))))

        if options.quiet:
            return 1

        printer = HexDumpPrinter(options, buffers[0], buffers[1])
        out(str(printer))

        if proc < 10.0:
            out(bad_chars_string)
        else:
            out(warn("Too many differences to guess bad chars correctly."))
        
    return 0
        
if __name__ == '__main__':
    sys.exit(main(sys.argv))

