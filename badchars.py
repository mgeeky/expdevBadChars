#!/usr/bin/python
#
# Bad characters matching tool capable of transforming input bytes from
# many different hexdump / hex string / escaped hex strings formats.
# To be used during exploit development stage when the shellcode gets corrupted
# due to filtered bytes. Additionally armed with modified LCS algoritm designed by
# Peter Van Eeckhoutte from Corelan.be (originally taken from his Mona.py).
#
# LICENSE note:
#   This program contains adapted source code taken from Mona.py script, that was
#   originally written by Peter Van Eeckhoutte - Corelan GCV.
#   Specifically his MemoryComparator class and couple of supplying routines like
#   draw_chunk_table or guess_bad_chars.
#   One can refer to the original Mona's license here:
#       https://github.com/corelan/mona/blob/master/LICENSE  
#
# Written by: 
# Mariusz B. / mgeeky, 2017
#

import re
import sys
import types
import string
import os.path
import itertools
from optparse import OptionParser
from operator import itemgetter
from collections import defaultdict, namedtuple

VERSION = '0.2'

options = { }
filenames = []
buffers = [[], []]

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def strip_colors(line):
        line = line.replace(bcolors.HEADER, '')
        line = line.replace(bcolors.OKBLUE, '')
        line = line.replace(bcolors.OKGREEN, '')
        line = line.replace(bcolors.WARNING, '')
        line = line.replace(bcolors.FAIL, '')
        return line.replace(bcolors.ENDC, '')

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
        #modify from r'^(?:((?:0x[0-9a-f]{1,8}\s[<>\w\+]+)):\s*)?((?:0x[0-9a-f]{8},?\s*)+)$
        #include match of GDB address 
        'dword': r'^(?:((?:0x[0-9a-f]{1,8}\s[<>\w\+]+)|(?:0x[0-9a-f]{1,8})):\s*)?((?:0x[0-9a-f]{8},?\s*)+)$',
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

        #do not normalize input on raw format to prevent input tempering
        if str(format).lower() != "raw":
            self.normalize_input()

        if format:
            out(dbg("Using user-specified format: %s" % format))

            if str(format).lower() == "raw":
                self.format = "raw"

            else:		
                try:
                    self.format = BytesParser.interpret_format_name(format)
                except Exception, e:
                    out(dbg(str(e)))

                #exit when user-specified format not in both formats_rex and formats_aliases 
                assert (format in BytesParser.formats_rex.keys() or self.format is not None), \
                        "Format '%s' is not implemented." % format
                    
            if self.format is None:
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
        for k, v in BytesParser.formats_aliases.items():
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
        """
        modify from r'((?:0x[0-9a-f]{8},?\s*))
        added constrain to remove match of gdb address format
        e.g, remove match of 0xffffd67a:

        0xffffd67a:     0xdfb8c2db      0xd9db029c      0x5bf42474      0x0bb1c933
        0xffffd68a:     0x031a4331      0xeb831a43      0xf62ae2fc      0x554d8309
        0xffffd69a:     0x39405b68      0x92f27cfd      0x8502ea8e      0x3b6b895f
        0xffffd6aa:     0x2b39ae29      0xabbd3121      0xc5d4531d      0x1a55ff4e
        0xffffd6ba:     0xfb10acc6      0x0000d225      0x96900000      0x4520f7fe
        0xffffd6ca:     0xd000f7fe      0x0001f7ff      0x83400000      0x00000804
        0xffffd6da:     0x83610000      0x84080804      0x00010804      0xd7040000
        0xffffd6ea:     0x8430ffff      0x84200804      0x45200804      0xd6fcf7fe
        0xffffd6fa:     0xd950ffff      0x0001f7ff      0xd83c0000      0x0000ffff
        0xffffd70a:     0xd8480000      0xde34ffff      0xde62ffff      0xde71ffff
        0xffffd71a:     0xde82ffff      0xde97ffff      0xdea1ffff      0xdeb4ffff
        0xffffd72a:     0xdebdffff      0xdec8ffff
            
        """
        for m in re.finditer(r'((?:0x[0-9a-f]{8}(?!:),?\s*))', line):
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

def memoized(func):
    ''' A function decorator to make a function cache it's return values.
    If a function returns a generator, it's transformed into a list and
    cached that way. '''
    cache = {}
    def wrapper(*args):
        if args in cache:
            return cache[args]
        val = func(*args)
        if isinstance(val, types.GeneratorType):
            val = list(val)
        cache[args] = val
        return val
    wrapper.__doc__ = func.__doc__
    wrapper.func_name = '%s_memoized' % func.func_name
    return wrapper

def bin2hex(binbytes):
    """
    Converts a binary string to a string of space-separated hexadecimal bytes.
    """
    if len(binbytes) > 0 and type(binbytes[0]) == type(''):
        return ' '.join('%02x' % ord(c) for c in binbytes)
    else:
        return ' '.join('%02x' % c for c in binbytes)

def bad_chars(comp):
    mapped_chunks = map(''.join, comp.guess_mapping())
    buffer1 = [chr(c) for c in buffers[0]]
    mapping = zip(buffer1, mapped_chunks)
    broken = [(i,x,y) for i,(x,y) in enumerate(mapping) if x != y]
    guessed_bc = guess_bad_chars(comp)

    return (broken, guessed_bc)

def rrange(x, y = 0):
    """ Creates a reversed range (from x - 1 down to y).
        Example:
        >>> rrange(10, 0) # => [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    """
    return range(x - 1, y - 1, -1)

def guess_bad_chars(comp):
    guessed_badchars = []
    ''' Tries to guess bad characters and outputs them '''
    bytes_in_changed_blocks = defaultdict(int)
    chunks = comp.get_chunks()
    last_unmodified = comp.get_last_unmodified_chunk()

    for i, c in enumerate(chunks):
        if c.unmodified: continue
        if i == last_unmodified + 1:
            # only report the first character as bad in the final corrupted chunk
            bytes_in_changed_blocks[c.xchunk[0]] += 1
            break
        for b in set(c.xchunk):
            bytes_in_changed_blocks[b] += 1

    # guess bad chars
    likely_bc = [char for char, count in bytes_in_changed_blocks.iteritems() if count > 2]
    if likely_bc:
        out(dbg("Very likely bad chars: %s" % bin2hex(sorted(likely_bc))))
        guessed_badchars += list(sorted(likely_bc))
        out(dbg("Possibly bad chars: %s" % bin2hex(sorted(bytes_in_changed_blocks))))

    guessed_badchars += list(sorted(bytes_in_changed_blocks))
    
    # list bytes already omitted from the input
    bytes_omitted_from_input = set(map(chr, range(0, 256))) - set(comp.x)
    if bytes_omitted_from_input:
        out(dbg("Bytes omitted from input: %s" % bin2hex(sorted(bytes_omitted_from_input))))
        guessed_badchars += list(sorted( bytes_omitted_from_input))
        
    # return list, use list(set(..)) to remove dups
    return list(set(guessed_badchars))

def shorten_bytes(bytes, size=8):
    if len(bytes) <= size: return bin2hex(bytes)
    return '%02x ... %02x' % (ord(bytes[0]), ord(bytes[-1]))

def draw_chunk_table(comp):
    ''' Outputs a table that compares the found memory chunks side-by-side
    in input file vs. memory '''
    table = [('', '', '', '', 'File', 'Memory', 'Note')]
    delims = (' ', ' ', ' ', ' | ', ' | ', ' | ', '')
    last_unmodified = comp.get_last_unmodified_chunk()
    for c in comp.get_chunks():
        if   c.dy == 0:    note = 'missing'
        elif c.dx > c.dy:  note = 'compacted'
        elif c.dx < c.dy:  note = 'expanded'
        elif c.unmodified: note = 'unmodified!'
        else:              note = 'corrupted'
        table.append((c.i, c.j, c.dx, c.dy, shorten_bytes(c.xchunk), shorten_bytes(c.ychunk), note))

    # draw the table
    sizes = tuple(max(len(str(c)) for c in col) for col in zip(*table))
    for i, row in enumerate(table):
        out('\t' + ''.join(str(x).ljust(size) + delim for x, size, delim in zip(row, sizes, delims)))
        if i == 0 or (i == last_unmodified + 1 and i < len(table)):
            out('\t' + '-' * (sum(sizes) + sum(len(d) for d in delims)))


#
# Memory comparison algorithm originally taken from Mona.py by Peter Van Eeckhoutte - Corelan GCV
# https://github.com/corelan/mona
#
# It utilizes modified Longest Common Subsequence algorithm to mark number of modifications over
# supplied input to let it be transformed into another input, as compared to.
#
class MemoryComparator(object):
    ''' Solve the memory comparison problem with a special dynamic programming
    algorithm similar to that for the LCS problem '''

    Chunk = namedtuple('Chunk', 'unmodified i j dx dy xchunk ychunk')

    move_to_gradient = {
        0: (0, 0),
        1: (0, 1),
        2: (1, 1),
        3: (2, 1),
    }

    def __init__(self, x, y):
        self.x, self.y = x, y

    @memoized
    def get_last_unmodified_chunk(self):
        ''' Returns the index of the last chunk of size > 1 that is unmodified '''
        try:
            return max(i for i, c in enumerate(self.get_chunks()) if c.unmodified and c.dx > 1)
        except:
            # no match
            return -1

    @memoized
    def get_grid(self):
        ''' Builds a 2-d suffix grid for our DP algorithm. '''
        x = self.x
        y = self.y[:len(x)*2]
        width, height  = len(x), len(y)
        values = [[0] * (width + 1) for j in range(height + 1)]
        moves  = [[0] * (width + 1) for j in range(height + 1)]
        equal  = [[x[i] == y[j] for i in range(width)] for j in range(height)]
        equal.append([False] * width)

        for j, i in itertools.product(rrange(height + 1), rrange(width + 1)):
            value = values[j][i]
            if i >= 1 and j >= 1:
                if equal[j-1][i-1]:
                    values[j-1][i-1] = value + 1
                    moves[j-1][i-1] = 2
                elif value > values[j][i-1]:
                    values[j-1][i-1] = value
                    moves[j-1][i-1] = 2
            if i >= 1 and not equal[j][i-1] and value - 2 > values[j][i-1]:
                values[j][i-1] = value - 2
                moves[j][i-1] = 1
            if i >= 1 and j >= 2 and not equal[j-2][i-1] and value - 1 > values[j-2][i-1]:
                values[j-2][i-1] = value - 1
                moves[j-2][i-1] = 3
        return (values, moves)

    @memoized
    def get_blocks(self):
        '''
            Compares two binary strings under the assumption that y is the result of
            applying the following transformations onto x:

             * change single bytes in x (likely)
             * expand single bytes in x to two bytes (less likely)
             * drop single bytes in x (even less likely)

            Returns a generator that yields elements of the form (unmodified, xdiff, ydiff),
            where each item represents a binary chunk with "unmodified" denoting whether the
            chunk is the same in both strings, "xdiff" denoting the size of the chunk in x
            and "ydiff" denoting the size of the chunk in y.

            Example:
            >>> x = "abcdefghijklm"
            >>> y = "mmmcdefgHIJZklm"
            >>> list(MemoryComparator(x, y).get_blocks())
            [(False, 2, 3), (True, 5, 5),
             (False, 3, 4), (True, 3, 3)]
        '''
        x, y = self.x, self.y
        _, moves = self.get_grid()

        # walk the grid
        path = []
        i, j = 0, 0
        while True:
            dy, dx = self.move_to_gradient[moves[j][i]]
            if dy == dx == 0: break
            path.append((dy == 1 and x[i] == y[j], dy, dx))
            j, i = j + dy, i + dx

        for i, j in zip(range(i, len(x)), itertools.count(j)):
            if j < len(y): path.append((x[i] == y[j], 1, 1))
            else:          path.append((False,        0, 1))

        i = j = 0
        for unmodified, subpath in itertools.groupby(path, itemgetter(0)):
            ydiffs = map(itemgetter(1), subpath)
            dx, dy = len(ydiffs), sum(ydiffs)
            yield unmodified, dx, dy
            i += dx
            j += dy

    @memoized
    def get_chunks(self):
        i = j = 0
        for unmodified, dx, dy in self.get_blocks():
            yield self.Chunk(unmodified, i, j, dx, dy, self.x[i:i+dx], self.y[j:j+dy])
            i += dx
            j += dy

    @memoized
    def guess_mapping(self):
        ''' Tries to guess how the bytes in x have been mapped to substrings in y by
            applying nasty heuristics.

            Examples:
            >>> list(MemoryComparator("abcdefghijklm", "mmmcdefgHIJZklm").guess_mapping())
            [('m', 'm'), ('m',), ('c',), ('d',), ('e',), ('f',), ('g',), ('H', 'I'), ('J',),
             ('Z',), ('k',), ('l',), ('m',)]
            >>> list(MemoryComparator("abcdefgcbadefg", "ABBCdefgCBBAdefg").guess_mapping())
            [('A',), ('B', 'B'), ('C',), ('d',), ('e',), ('f',), ('g',), ('C',), ('B', 'B'),
             ('A',), ('d',), ('e',), ('f',), ('g',)]
        '''
        x, y = self.x, self.y

        mappings_by_byte = defaultdict(lambda: defaultdict(int))
        for c in self.get_chunks():
            dx, dy = c.dx, c.dy
            # heuristics to detect expansions
            if dx < dy and dy - dx <= 3 and dy <= 5:
                for i, b in enumerate(c.xchunk):
                    slices = set()
                    for start in range(i, min(2*i + 1, dy)):
                        for size in range(1, min(dy - start + 1, 3)):
                            slc = tuple(c.ychunk[start:start+size])
                            if slc in slices: continue
                            mappings_by_byte[b][slc] += 1
                            slices.add(slc)

        for b, values in mappings_by_byte.iteritems():
            mappings_by_byte[b] = sorted(values.items(),
                                     key=lambda (value, count): (-count, -len(value)))

        for c in self.get_chunks():
            dx, dy, xchunk, ychunk = c.dx, c.dy, c.xchunk, c.ychunk
            if dx < dy:  # expansion
                # try to apply heuristics for small chunks
                if dx <= 10:
                    res = []
                    for b in xchunk:
                        if dx == dy or dy >= 2*dx: break
                        for value, count in mappings_by_byte[b]:
                            if tuple(ychunk[:len(value)]) != value: continue
                            res.append(value)
                            ychunk = ychunk[len(value):]
                            dy -= len(value)
                            break
                        else:
                            yield (ychunk[0],)
                            ychunk = ychunk[1:]
                            dy -= 1
                        dx -= 1
                    for c in res: yield c

                # ... or do it the stupid way. If n bytes were changed to m, simply do
                # as much drops/expansions as necessary at the beginning and than
                # yield the rest of the y chunk as single-byte modifications
                for k in range(dy - dx): yield tuple(ychunk[2*k:2*k+2])
                ychunk = ychunk[2*(dy - dx):]
            elif dx > dy:
                for _ in range(dx - dy): yield ()

            for b in ychunk: yield (b,)

class HexDumpPrinter:
    def __init__(self, options, good_buffer, bad_buffer):
        self.comparator = None
        self.fill_matching = ''
        if not options.dont_use_lcs:
            self.dump1 = []
            self.dump2 = []

            if not options.match_empty:
                self.fill_matching = ' ' 
            else:
                self.fill_matching = '0' 
            self.use_comparator()
        else:
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

    def get_comparator(self): return self.comparator
        
    def use_comparator(self):
        buffer1 = [chr(c) for c in buffers[0]]
        buffer2 = [chr(c) for c in buffers[1]]

        comp = MemoryComparator(buffer1, buffer2)
        self.comparator = comp

        mapped_chunks = map(''.join, comp.guess_mapping())
        mapping = zip(buffer1, mapped_chunks)

        self.construct_comparator_dump(mapping)

        broken = [(i,x,y) for i,(x,y) in enumerate(mapping) if x != y]
        return (comp, broken, mapped_chunks)


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
    def extract_chunks(iterable):
        """ Retrieves chunks of the given :size from the :iterable """
        fill = object()
        gen = itertools.izip_longest(fillvalue=fill, *([iter(iterable)] * 16))
        return (tuple(x for x in chunk if x != fill) for chunk in gen)

    def construct_comparator_dump(self, mapping):
        def toprint(x, src):
            c = x
            if len(c) == 0: c = ' '
            elif len(c) == 2: c = x[1]

            if ord(c) >= 0x20 and ord(c) < 0x7f:
                return c
            else: 
                return '.'

        for i, chunk in enumerate(HexDumpPrinter.extract_chunks(mapping)):
            chunk = list(chunk)  # save generator result in a list
            src, mapped = zip(*chunk)
            values = []
            for left, right in zip(src, mapped):
                if   left == right:   values.append('')             # byte matches original
                elif len(right) == 0: values.append('-1')           # byte dropped
                elif len(right) == 2: values.append('+1')           # byte expanded
                else:                 values.append(bin2hex(right)) # byte modified

            line1 = '%04x' % (i * 16) + ' | ' + bin2hex(src).ljust(49, ' ')
            line2 = '%04x' % (i * 16) + ' | ' + ' '.join(sym.ljust(2, self.fill_matching) for sym in values)

            line1 += '| ' + ''.join(map(lambda x: x if ord(x) >= 0x20 and ord(x) < 0x7f else '.', src)).ljust(16, ' ')
            ascii2 = '| '
            for i in range(len(values)): ascii2 += toprint(values[i], src[i])
            for i in range(len(values), 16): ascii2 += ' '
            line2 = line2.ljust(56, ' ')
            line2 += ascii2

            #out(dbg("Line1: ('%s')" % line1))
            #out(dbg("Line2: ('%s')" % line2))

            self.dump1.append(line1)
            self.dump2.append(line2)


    @staticmethod
    def wide_line(letter, d1, d2):
        d1t = d1.split(' | ')
        d2t = d2.split(' | ')

        if options.colored:
            letter = bcolors.HEADER + letter + bcolors.ENDC

        padding = ' ' * (17 - len(bcolors.strip_colors(d1t[2])))
        return '{}{} | {} | {}{}| {} | {}'.format(letter, d1t[0], d1t[1], d1t[2], padding, d2t[1], d2t[2])

    @staticmethod
    def extract_bytes(line):
        linet = line.split(' | ')
        strbytes = [linet[1][i:i+2] for i in range(0, len(linet[1]), 3)]
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

        return '{}{} | {} | {}'.format(letter, address, bytes_line, ascii.ljust(16))

    def highlight_differences(self, d1, d2):
        if d1 != d2:
            d1t = d1.split(' | ')
            d2t = d2.split(' | ')

            d1bytes = HexDumpPrinter.extract_bytes(d1)
            d2bytes = HexDumpPrinter.extract_bytes(d2)
            minlen = min(len(d1bytes), len(d2bytes))

            for i in range(minlen):
                if d1bytes[i] != d2bytes[i]:
                    if not options.dont_use_lcs and d2bytes[i] == self.fill_matching * len(d2bytes[i]):
                        continue
                    d1bytes[i] = self.good_start_diff + d1bytes[i] + self.good_stop_diff
                    d2bytes[i] = self.bad_start_diff + d2bytes[i] + self.bad_stop_diff

            d1 = HexDumpPrinter.reconstruct_line(self.address_good, d1, d1bytes)
            d2 = HexDumpPrinter.reconstruct_line(self.address_bad, d2, d2bytes)
        
        return (d1, d2)
    
    def __str__(self):
        buff = ''

        if not options.wide:
            buff += ' ' * 5 + ' | ' + ' '.join(['%02x' % x for x in range(16)]) + '  |\n'
            buff += ' ' * 5 + ' |' + '-' * 50 + '|\n'
        else:
            buff += ' ' * 5 + ' | ' + ' '.join(['%02x' % x for x in range(16)]) + '  |'
            buff = buff + ' ' * 12 + buff + '\n'
            buff += ' ' * 5 + ' |' + '-' * 50 + '|' + ' ' * 12
            buff += ' ' * 5 + ' |' + '-' * 50 + '|\n'

        for i in range(self.minlen):
            d1 = self.dump1[i]
            d2 = self.dump2[i]
            d1t = d1.split(' | ')
            d2t = d2.split(' | ')

            if d1 == d2 or (d2t[1].count(' ') == len(d2t[1])):
                if not options.wide:
                    buff += ' ' + d1
                    if options.match_empty:
                        buff += '\n ' + d2
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
    parser.add_option("", "--format1", metavar="FORMAT", dest="format1", default=None, 
                        help="Enforce specific format on first buffer.")
    parser.add_option("", "--format2", metavar="FORMAT", dest="format2", default=None, 
                        help="Enforce specific format on second buffer.")
    parser.add_option("-C", "--nocolors", action="store_false", dest="colored", default=True, 
                        help="Don't apply colors to the comparison output.")
    parser.add_option("-w", "--wide", action="store_true", dest="wide", default=False, 
                        help="Wide mode, display hex dumps next to each other.")
    parser.add_option("-e", "--match-empty", action="store_true", dest="match_empty", default=False, 
                        help="Print matching bytes as empty line from bad_buffer.")
    parser.add_option("-n", "--no-lcs", action="store_true", dest="dont_use_lcs", default=False, 
                        help="Don't use LCS (Longest Common Subsequence) algorithm in hex dump printing. Go with simple comparison.")
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

def banner():
    sys.stderr.write("\n\t:: BadChars.py (v:%s) - Exploit Development Bad Characters hunting tool." % VERSION)
    sys.stderr.write("\n\t\tEquipped with Corelan.be Mona's buffers comparison LCS-based algorithm\n\n")

def main(argv):
    banner()
    if not parse_options():
        return 1

    buffers[0].extend(fetch_file(filenames[0], 'good_buffer', options.format1))
    buffers[1].extend(fetch_file(filenames[1], 'bad_buffer', options.format2))

    if len(buffers[0]) != len(buffers[1]):
        out("\n"+warn("Specified buffer files differ in contents length (%d, %d)!" \
                    % (len(buffers[0]), len(buffers[1]))))
    else:
        out(ok("Buffers are of same size: %d bytes." % len(buffers[0])))
        
    res, bad_chars_dict = check_if_match()
    
    if not res:
        out(ok("\t\nBuffers match. No Bad characters found.\n"))
        return 0
    else:
        bad_chars_string = ''
        bad_chars_flatten = filter(lambda x: x != -1, bad_chars_dict.keys())

        if options.quiet:
            return 1

        printer = HexDumpPrinter(options, buffers[0], buffers[1])

        minlen = min(len(buffers[0]), len(buffers[1]))
        proc = (float(res)/float(minlen) * 100.0)

        if not options.dont_use_lcs:
            (broken, values) = bad_chars(printer.get_comparator())
            bad_chars_flatten = [ord(c) for c in values]
            bad_chars_dict = {}

        if not options.quiet:
            chars = ', '.join(['0x%02x' % c for c in bad_chars_flatten])
            bad_chars_string += _out("Likely to be bad chars: " + bcolors.HEADER + chars + "\n", bcolors.WARNING)

            if len(bad_chars_dict.keys()) > 0:
                bad_chars_string += _out("Found mappings:\n", bcolors.WARNING)

                tochar = lambda x: x if ((x > 0 and x < 256) and (chr(x) in string.printable)) else '.'
                added = set()
                for k, v in bad_chars_dict.items():
                    a = k
                    a1 = tochar(k)
                    for b in v:
                        b1 = tochar(b)
                        if (a, b) not in added and a != -1:
                            bad_chars_string += "\t0x%02x (%s) => 0x%02x (%s)\n" % (a, a1, b, b1)
                            added.add((a,b))

        if proc != 100.0:
            out(err("\n\tBuffers differ! Found at least %d differences (%d/%d, %0.2f%%) and %d bad chars\n" \
                    % (res, res, minlen, proc, len(bad_chars_flatten))))
        else:
            out(err("\n\tBuffers differ entirely.\n"))

        out(str(printer))

        if options.dont_use_lcs:
            if proc < 10.0:
                out(bad_chars_string)
            else:
                out(warn("Too many differences to guess bad chars correctly."))
        else:
            draw_chunk_table(printer.get_comparator())
        
    return 0
        
if __name__ == '__main__':
    sys.exit(main(sys.argv))

