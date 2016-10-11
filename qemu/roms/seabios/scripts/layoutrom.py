#!/usr/bin/env python
# Script to analyze code and arrange ld sections.
#
# Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

import operator
import sys

# LD script headers/trailers
COMMONHEADER = """
/* DO NOT EDIT!  This is an autogenerated file.  See tools/layoutrom.py. */
OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH("i386")
SECTIONS
{
"""
COMMONTRAILER = """

        /* Discard regular data sections to force a link error if
         * code attempts to access data not marked with VAR16 (or other
         * appropriate macro)
         */
        /DISCARD/ : {
                *(.text*) *(.data*) *(.bss*) *(.rodata*)
                *(COMMON) *(.discard*) *(.eh_frame) *(.note*)
                }
}
"""


######################################################################
# Determine section locations
######################################################################

# Align 'pos' to 'alignbytes' offset
def alignpos(pos, alignbytes):
    mask = alignbytes - 1
    return (pos + mask) & ~mask

# Determine the final addresses for a list of sections that end at an
# address.
def setSectionsStart(sections, endaddr, minalign=1, segoffset=0):
    totspace = 0
    for section in sections:
        if section.align > minalign:
            minalign = section.align
        totspace = alignpos(totspace, section.align) + section.size
    startaddr = int((endaddr - totspace) / minalign) * minalign
    curaddr = startaddr
    for section in sections:
        curaddr = alignpos(curaddr, section.align)
        section.finalloc = curaddr
        section.finalsegloc = curaddr - segoffset
        curaddr += section.size
    return startaddr, minalign

# The 16bit code can't exceed 64K of space.
BUILD_BIOS_ADDR = 0xf0000
BUILD_BIOS_SIZE = 0x10000
BUILD_ROM_START = 0xc0000
BUILD_LOWRAM_END = 0xa0000
# Space to reserve in f-segment for dynamic allocations
BUILD_MIN_BIOSTABLE = 2048

# Layout the 16bit code.  This ensures sections with fixed offset
# requirements are placed in the correct location.  It also places the
# 16bit code as high as possible in the f-segment.
def fitSections(sections, fillsections):
    # fixedsections = [(addr, section), ...]
    fixedsections = []
    for section in sections:
        if section.name.startswith('.fixedaddr.'):
            addr = int(section.name[11:], 16)
            section.finalloc = addr + BUILD_BIOS_ADDR
            section.finalsegloc = addr
            fixedsections.append((addr, section))
            if section.align != 1:
                print("Error: Fixed section %s has non-zero alignment (%d)" % (
                    section.name, section.align))
                sys.exit(1)
    fixedsections.sort(key=operator.itemgetter(0))
    firstfixed = fixedsections[0][0]

    # Find freespace in fixed address area
    # fixedAddr = [(freespace, section), ...]
    fixedAddr = []
    for i in range(len(fixedsections)):
        fixedsectioninfo = fixedsections[i]
        addr, section = fixedsectioninfo
        if i == len(fixedsections) - 1:
            nextaddr = BUILD_BIOS_SIZE
        else:
            nextaddr = fixedsections[i+1][0]
        avail = nextaddr - addr - section.size
        fixedAddr.append((avail, section))
    fixedAddr.sort(key=operator.itemgetter(0))

    # Attempt to fit other sections into fixed area
    canrelocate = [(section.size, section.align, section.name, section)
                   for section in fillsections]
    canrelocate.sort()
    canrelocate = [section for size, align, name, section in canrelocate]
    totalused = 0
    for freespace, fixedsection in fixedAddr:
        addpos = fixedsection.finalsegloc + fixedsection.size
        totalused += fixedsection.size
        nextfixedaddr = addpos + freespace
#        print("Filling section %x uses %d, next=%x, available=%d" % (
#            fixedsection.finalloc, fixedsection.size, nextfixedaddr, freespace))
        while 1:
            canfit = None
            for fitsection in canrelocate:
                if addpos + fitsection.size > nextfixedaddr:
                    # Can't fit and nothing else will fit.
                    break
                fitnextaddr = alignpos(addpos, fitsection.align) + fitsection.size
#                print("Test %s - %x vs %x" % (
#                    fitsection.name, fitnextaddr, nextfixedaddr))
                if fitnextaddr > nextfixedaddr:
                    # This item can't fit.
                    continue
                canfit = (fitnextaddr, fitsection)
            if canfit is None:
                break
            # Found a section that can fit.
            fitnextaddr, fitsection = canfit
            canrelocate.remove(fitsection)
            fitsection.finalloc = addpos + BUILD_BIOS_ADDR
            fitsection.finalsegloc = addpos
            addpos = fitnextaddr
            totalused += fitsection.size
#            print("    Adding %s (size %d align %d) pos=%x avail=%d" % (
#                fitsection[2], fitsection[0], fitsection[1]
#                , fitnextaddr, nextfixedaddr - fitnextaddr))

    # Report stats
    total = BUILD_BIOS_SIZE-firstfixed
    slack = total - totalused
    print ("Fixed space: 0x%x-0x%x  total: %d  slack: %d"
           "  Percent slack: %.1f%%" % (
            firstfixed, BUILD_BIOS_SIZE, total, slack,
            (float(slack) / total) * 100.0))

    return firstfixed + BUILD_BIOS_ADDR

# Return the subset of sections with a given category
def getSectionsCategory(sections, category):
    return [section for section in sections if section.category == category]

# Return the subset of sections with a given name prefix
def getSectionsPrefix(sections, prefix):
    return [section for section in sections
            if section.name.startswith(prefix)]

# The sections (and associated information) to be placed in output rom
class LayoutInfo:
    genreloc = None
    sections16 = sec16_start = sec16_align = None
    sections32seg = sec32seg_start = sec32seg_align = None
    sections32flat = sec32flat_start = sec32flat_align = None
    sections32init = sec32init_start = sec32init_align = None
    sections32low = sec32low_start = sec32low_align = None
    sections32fseg = sec32fseg_start = sec32fseg_align = None
    zonefseg_start = zonefseg_end = None
    final_readonly_start = None
    zonelow_base = final_sec32low_start = None
    exportsyms = varlowsyms = None

# Determine final memory addresses for sections
def doLayout(sections, config, genreloc):
    li = LayoutInfo()
    li.genreloc = genreloc
    # Determine 16bit positions
    li.sections16 = getSectionsCategory(sections, '16')
    textsections = getSectionsPrefix(li.sections16, '.text.')
    rodatasections = (
        getSectionsPrefix(li.sections16, '.rodata.str1.1')
        + getSectionsPrefix(li.sections16, '.rodata.__func__.')
        + getSectionsPrefix(li.sections16, '.rodata.__PRETTY_FUNCTION__.'))
    datasections = getSectionsPrefix(li.sections16, '.data16.')
    fixedsections = getSectionsPrefix(li.sections16, '.fixedaddr.')

    firstfixed = fitSections(fixedsections, textsections)
    remsections = [s for s in textsections+rodatasections+datasections
                   if s.finalloc is None]
    li.sec16_start, li.sec16_align = setSectionsStart(
        remsections, firstfixed, segoffset=BUILD_BIOS_ADDR)

    # Determine 32seg positions
    li.sections32seg = getSectionsCategory(sections, '32seg')
    textsections = getSectionsPrefix(li.sections32seg, '.text.')
    rodatasections = (
        getSectionsPrefix(li.sections32seg, '.rodata.str1.1')
        + getSectionsPrefix(li.sections32seg, '.rodata.__func__.')
        + getSectionsPrefix(li.sections32seg, '.rodata.__PRETTY_FUNCTION__.'))
    datasections = getSectionsPrefix(li.sections32seg, '.data32seg.')

    li.sec32seg_start, li.sec32seg_align = setSectionsStart(
        textsections + rodatasections + datasections, li.sec16_start
        , segoffset=BUILD_BIOS_ADDR)

    # Determine "fseg memory" data positions
    li.sections32fseg = getSectionsCategory(sections, '32fseg')

    li.sec32fseg_start, li.sec32fseg_align = setSectionsStart(
        li.sections32fseg, li.sec32seg_start, 16
        , segoffset=BUILD_BIOS_ADDR)

    # Determine 32flat runtime positions
    li.sections32flat = getSectionsCategory(sections, '32flat')
    textsections = getSectionsPrefix(li.sections32flat, '.text.')
    rodatasections = getSectionsPrefix(li.sections32flat, '.rodata')
    datasections = getSectionsPrefix(li.sections32flat, '.data.')
    bsssections = getSectionsPrefix(li.sections32flat, '.bss.')

    li.sec32flat_start, li.sec32flat_align = setSectionsStart(
        textsections + rodatasections + datasections + bsssections
        , li.sec32fseg_start, 16)

    # Determine 32flat init positions
    li.sections32init = getSectionsCategory(sections, '32init')
    init32_textsections = getSectionsPrefix(li.sections32init, '.text.')
    init32_rodatasections = getSectionsPrefix(li.sections32init, '.rodata')
    init32_datasections = getSectionsPrefix(li.sections32init, '.data.')
    init32_bsssections = getSectionsPrefix(li.sections32init, '.bss.')

    li.sec32init_start, li.sec32init_align = setSectionsStart(
        init32_textsections + init32_rodatasections
        + init32_datasections + init32_bsssections
        , li.sec32flat_start, 16)

    # Determine location of ZoneFSeg memory.
    li.zonefseg_end = li.sec32flat_start
    if not genreloc:
        li.zonefseg_end = li.sec32init_start
    li.zonefseg_start = BUILD_BIOS_ADDR
    if li.zonefseg_start + BUILD_MIN_BIOSTABLE > li.zonefseg_end:
        # Not enough ZoneFSeg space - force a minimum space.
        li.zonefseg_end = li.sec32fseg_start
        li.zonefseg_start = li.zonefseg_end - BUILD_MIN_BIOSTABLE
        li.sec32flat_start, li.sec32flat_align = setSectionsStart(
            textsections + rodatasections + datasections + bsssections
            , li.zonefseg_start, 16)
        li.sec32init_start, li.sec32init_align = setSectionsStart(
            init32_textsections + init32_rodatasections
            + init32_datasections + init32_bsssections
            , li.sec32flat_start, 16)
    li.final_readonly_start = min(BUILD_BIOS_ADDR, li.sec32flat_start)
    if not genreloc:
        li.final_readonly_start = min(BUILD_BIOS_ADDR, li.sec32init_start)

    # Determine "low memory" data positions
    li.sections32low = getSectionsCategory(sections, '32low')
    sec32low_end = li.sec32init_start
    if config.get('CONFIG_MALLOC_UPPERMEMORY'):
        final_sec32low_end = li.final_readonly_start
        zonelow_base = final_sec32low_end - 64*1024
        li.zonelow_base = max(BUILD_ROM_START, alignpos(zonelow_base, 2*1024))
    else:
        final_sec32low_end = BUILD_LOWRAM_END
        li.zonelow_base = final_sec32low_end - 64*1024
    relocdelta = final_sec32low_end - sec32low_end
    li.sec32low_start, li.sec32low_align = setSectionsStart(
        li.sections32low, sec32low_end, 16
        , segoffset=li.zonelow_base - relocdelta)
    li.final_sec32low_start = li.sec32low_start + relocdelta

    # Print statistics
    size16 = BUILD_BIOS_ADDR + BUILD_BIOS_SIZE - li.sec16_start
    size32seg = li.sec16_start - li.sec32seg_start
    size32fseg = li.sec32seg_start - li.sec32fseg_start
    size32flat = li.sec32fseg_start - li.sec32flat_start
    size32init = li.sec32flat_start - li.sec32init_start
    sizelow = sec32low_end - li.sec32low_start
    print("16bit size:           %d" % size16)
    print("32bit segmented size: %d" % size32seg)
    print("32bit flat size:      %d" % size32flat)
    print("32bit flat init size: %d" % size32init)
    print("Lowmem size:          %d" % sizelow)
    print("f-segment var size:   %d" % size32fseg)
    return li


######################################################################
# Linker script output
######################################################################

# Write LD script includes for the given cross references
def outXRefs(sections, useseg=0, exportsyms=[], forcedelta=0):
    xrefs = dict([(symbol.name, symbol) for symbol in exportsyms])
    out = ""
    for section in sections:
        for reloc in section.relocs:
            symbol = reloc.symbol
            if (symbol.section is not None
                and (symbol.section.fileid != section.fileid
                     or symbol.name != reloc.symbolname)):
                xrefs[reloc.symbolname] = symbol
    for symbolname, symbol in xrefs.items():
        loc = symbol.section.finalloc
        if useseg:
            loc = symbol.section.finalsegloc
        out += "%s = 0x%x ;\n" % (symbolname, loc + forcedelta + symbol.offset)
    return out

# Write LD script includes for the given sections using relative offsets
def outRelSections(sections, startsym, useseg=0):
    sections = [(section.finalloc, section) for section in sections
                if section.finalloc is not None]
    sections.sort(key=operator.itemgetter(0))
    out = ""
    for addr, section in sections:
        loc = section.finalloc
        if useseg:
            loc = section.finalsegloc
        out += ". = ( 0x%x - %s ) ;\n" % (loc, startsym)
        if section.name == '.rodata.str1.1':
            out += "_rodata = . ;\n"
        out += "*(%s)\n" % (section.name,)
    return out

# Build linker script output for a list of relocations.
def strRelocs(outname, outrel, relocs):
    relocs.sort()
    return ("        %s_start = ABSOLUTE(.) ;\n" % (outname,)
            + "".join(["LONG(0x%x - %s)\n" % (pos, outrel)
                       for pos in relocs])
            + "        %s_end = ABSOLUTE(.) ;\n" % (outname,))

# Find all relocations in the given sections with the given attributes
def getRelocs(sections, type=None, category=None, notcategory=None):
    out = []
    for section in sections:
        for reloc in section.relocs:
            if reloc.symbol.section is None:
                continue
            destcategory = reloc.symbol.section.category
            if ((type is None or reloc.type == type)
                and (category is None or destcategory == category)
                and (notcategory is None or destcategory != notcategory)):
                out.append(section.finalloc + reloc.offset)
    return out

# Return the start address and minimum alignment for a set of sections
def getSectionsStart(sections, defaddr=0):
    return min([section.finalloc for section in sections
                if section.finalloc is not None] or [defaddr])

# Output the linker scripts for all required sections.
def writeLinkerScripts(li, out16, out32seg, out32flat):
    # Write 16bit linker script
    out = outXRefs(li.sections16, useseg=1) + """
    zonelow_base = 0x%x ;
    _zonelow_seg = 0x%x ;

    code16_start = 0x%x ;
    .text16 code16_start : {
%s
    }
""" % (li.zonelow_base,
       int(li.zonelow_base / 16),
       li.sec16_start - BUILD_BIOS_ADDR,
       outRelSections(li.sections16, 'code16_start', useseg=1))
    outfile = open(out16, 'w')
    outfile.write(COMMONHEADER + out + COMMONTRAILER)
    outfile.close()

    # Write 32seg linker script
    out = outXRefs(li.sections32seg, useseg=1) + """
    code32seg_start = 0x%x ;
    .text32seg code32seg_start : {
%s
    }
""" % (li.sec32seg_start - BUILD_BIOS_ADDR,
       outRelSections(li.sections32seg, 'code32seg_start', useseg=1))
    outfile = open(out32seg, 'w')
    outfile.write(COMMONHEADER + out + COMMONTRAILER)
    outfile.close()

    # Write 32flat linker script
    sections32all = (li.sections32flat + li.sections32init + li.sections32fseg)
    sec32all_start = li.sec32low_start
    relocstr = ""
    if li.genreloc:
        # Generate relocations
        absrelocs = getRelocs(
            li.sections32init, type='R_386_32', category='32init')
        relrelocs = getRelocs(
            li.sections32init, type='R_386_PC32', notcategory='32init')
        initrelocs = getRelocs(
            li.sections32flat + li.sections32low + li.sections16
            + li.sections32seg + li.sections32fseg, category='32init')
        relocstr = (strRelocs("_reloc_abs", "code32init_start", absrelocs)
                    + strRelocs("_reloc_rel", "code32init_start", relrelocs)
                    + strRelocs("_reloc_init", "code32flat_start", initrelocs))
        numrelocs = len(absrelocs + relrelocs + initrelocs)
        sec32all_start -= numrelocs * 4
    out = outXRefs(li.sections32low, exportsyms=li.varlowsyms
                   , forcedelta=li.final_sec32low_start-li.sec32low_start)
    out += outXRefs(sections32all, exportsyms=li.exportsyms) + """
    _reloc_min_align = 0x%x ;
    zonefseg_start = 0x%x ;
    zonefseg_end = 0x%x ;
    zonelow_base = 0x%x ;
    final_varlow_start = 0x%x ;
    final_readonly_start = 0x%x ;

    code32flat_start = 0x%x ;
    .text code32flat_start : {
%s
        varlow_start = ABSOLUTE(.) ;
%s
        varlow_end = ABSOLUTE(.) ;
        code32init_start = ABSOLUTE(.) ;
%s
        code32init_end = ABSOLUTE(.) ;
%s
%s
        . = ( 0x%x - code32flat_start ) ;
        *(.text32seg)
        . = ( 0x%x - code32flat_start ) ;
        *(.text16)
        code32flat_end = ABSOLUTE(.) ;
    } :text
""" % (li.sec32init_align,
       li.zonefseg_start,
       li.zonefseg_end,
       li.zonelow_base,
       li.final_sec32low_start,
       li.final_readonly_start,
       sec32all_start,
       relocstr,
       outRelSections(li.sections32low, 'code32flat_start'),
       outRelSections(li.sections32init, 'code32flat_start'),
       outRelSections(li.sections32flat, 'code32flat_start'),
       outRelSections(li.sections32fseg, 'code32flat_start'),
       li.sec32seg_start,
       li.sec16_start)
    out = COMMONHEADER + out + COMMONTRAILER + """
ENTRY(entry_elf)
PHDRS
{
        text PT_LOAD AT ( code32flat_start ) ;
}
"""
    outfile = open(out32flat, 'w')
    outfile.write(out)
    outfile.close()


######################################################################
# Detection of init code
######################################################################

def markRuntime(section, sections, chain=[]):
    if (section is None or not section.keep or section.category is not None
        or '.init.' in section.name or section.fileid != '32flat'):
        return
    if '.data.varinit.' in section.name:
        print("ERROR: %s is VARVERIFY32INIT but used from %s" % (
            section.name, chain))
        sys.exit(1)
    section.category = '32flat'
    # Recursively mark all sections this section points to
    for reloc in section.relocs:
        markRuntime(reloc.symbol.section, sections, chain + [section.name])

def findInit(sections):
    # Recursively find and mark all "runtime" sections.
    for section in sections:
        if ('.data.varlow.' in section.name or '.data.varfseg.' in section.name
            or '.runtime.' in section.name or '.export.' in section.name):
            markRuntime(section, sections)
    for section in sections:
        if section.category is not None:
            continue
        if section.fileid == '32flat':
            section.category = '32init'
        else:
            section.category = section.fileid


######################################################################
# Section garbage collection
######################################################################

CFUNCPREFIX = [('_cfunc16_', 0), ('_cfunc32seg_', 1), ('_cfunc32flat_', 2)]

# Find and keep the section associated with a symbol (if available).
def keepsymbol(reloc, infos, pos, isxref):
    symbolname = reloc.symbolname
    mustbecfunc = 0
    for symprefix, needpos in CFUNCPREFIX:
        if symbolname.startswith(symprefix):
            if needpos != pos:
                return -1
            symbolname = symbolname[len(symprefix):]
            mustbecfunc = 1
            break
    symbol = infos[pos][1].get(symbolname)
    if (symbol is None or symbol.section is None
        or symbol.section.name.startswith('.discard.')):
        return -1
    isdestcfunc = (symbol.section.name.startswith('.text.')
                   and not symbol.section.name.startswith('.text.asm.'))
    if ((mustbecfunc and not isdestcfunc)
        or (not mustbecfunc and isdestcfunc and isxref)):
        return -1

    reloc.symbol = symbol
    keepsection(symbol.section, infos, pos)
    return 0

# Note required section, and recursively set all referenced sections
# as required.
def keepsection(section, infos, pos=0):
    if section.keep:
        # Already kept - nothing to do.
        return
    section.keep = 1
    # Keep all sections that this section points to
    for reloc in section.relocs:
        ret = keepsymbol(reloc, infos, pos, 0)
        if not ret:
            continue
        # Not in primary sections - it may be a cross 16/32 reference
        ret = keepsymbol(reloc, infos, (pos+1)%3, 1)
        if not ret:
            continue
        ret = keepsymbol(reloc, infos, (pos+2)%3, 1)
        if not ret:
            continue

# Determine which sections are actually referenced and need to be
# placed into the output file.
def gc(info16, info32seg, info32flat):
    # infos = ((sections16, symbols16), (sect32seg, sym32seg)
    #          , (sect32flat, sym32flat))
    infos = (info16, info32seg, info32flat)
    # Start by keeping sections that are globally visible.
    for section in info16[0]:
        if section.name.startswith('.fixedaddr.') or '.export.' in section.name:
            keepsection(section, infos)
    return [section for section in info16[0]+info32seg[0]+info32flat[0]
            if section.keep]


######################################################################
# Startup and input parsing
######################################################################

class Section:
    name = size = alignment = fileid = relocs = None
    finalloc = finalsegloc = category = keep = None
class Reloc:
    offset = type = symbolname = symbol = None
class Symbol:
    name = offset = section = None

# Read in output from objdump
def parseObjDump(file, fileid):
    # sections = [section, ...]
    sections = []
    sectionmap = {}
    # symbols[symbolname] = symbol
    symbols = {}

    state = None
    for line in file.readlines():
        line = line.rstrip()
        if line == 'Sections:':
            state = 'section'
            continue
        if line == 'SYMBOL TABLE:':
            state = 'symbol'
            continue
        if line.startswith('RELOCATION RECORDS FOR ['):
            sectionname = line[24:-2]
            if sectionname.startswith('.debug_'):
                # Skip debugging sections (to reduce parsing time)
                state = None
                continue
            state = 'reloc'
            relocsection = sectionmap[sectionname]
            continue

        if state == 'section':
            try:
                idx, name, size, vma, lma, fileoff, align = line.split()
                if align[:3] != '2**':
                    continue
                section = Section()
                section.name = name
                section.size = int(size, 16)
                section.align = 2**int(align[3:])
                section.fileid = fileid
                section.relocs = []
                sections.append(section)
                sectionmap[name] = section
            except ValueError:
                pass
            continue
        if state == 'symbol':
            try:
                parts = line[17:].split()
                if len(parts) == 3:
                    sectionname, size, name = parts
                elif len(parts) == 4 and parts[2] == '.hidden':
                    sectionname, size, hidden, name = parts
                else:
                    continue
                symbol = Symbol()
                symbol.size = int(size, 16)
                symbol.offset = int(line[:8], 16)
                symbol.name = name
                symbol.section = sectionmap.get(sectionname)
                symbols[name] = symbol
            except ValueError:
                pass
            continue
        if state == 'reloc':
            try:
                off, type, symbolname = line.split()
                reloc = Reloc()
                reloc.offset = int(off, 16)
                reloc.type = type
                reloc.symbolname = symbolname
                reloc.symbol = symbols.get(symbolname)
                if reloc.symbol is None:
                    # Some binutils (2.20.1) give section name instead
                    # of a symbol - create a dummy symbol.
                    reloc.symbol = symbol = Symbol()
                    symbol.size = 0
                    symbol.offset = 0
                    symbol.name = symbolname
                    symbol.section = sectionmap.get(symbolname)
                    symbols[symbolname] = symbol
                relocsection.relocs.append(reloc)
            except ValueError:
                pass
    return sections, symbols

# Parser for constants in simple C header files.
def scanconfig(file):
    f = open(file, 'r')
    opts = {}
    for l in f.readlines():
        parts = l.split()
        if len(parts) != 3:
            continue
        if parts[0] != '#define':
            continue
        value = parts[2]
        if value.isdigit() or (value.startswith('0x') and value[2:].isdigit()):
            value = int(value, 0)
        opts[parts[1]] = value
    return opts

def main():
    # Get output name
    in16, in32seg, in32flat, cfgfile, out16, out32seg, out32flat = sys.argv[1:]

    # Read in the objdump information
    infile16 = open(in16, 'r')
    infile32seg = open(in32seg, 'r')
    infile32flat = open(in32flat, 'r')

    # infoX = (sections, symbols)
    info16 = parseObjDump(infile16, '16')
    info32seg = parseObjDump(infile32seg, '32seg')
    info32flat = parseObjDump(infile32flat, '32flat')

    # Read kconfig config file
    config = scanconfig(cfgfile)

    # Figure out which sections to keep.
    sections = gc(info16, info32seg, info32flat)

    # Separate 32bit flat into runtime and init parts
    findInit(sections)

    # Note "low memory" and "fseg memory" parts
    for section in getSectionsPrefix(sections, '.data.varlow.'):
        section.category = '32low'
    for section in getSectionsPrefix(sections, '.data.varfseg.'):
        section.category = '32fseg'

    # Determine the final memory locations of each kept section.
    genreloc = '_reloc_abs_start' in info32flat[1]
    li = doLayout(sections, config, genreloc)

    # Exported symbols
    li.exportsyms = [symbol for symbol in info16[1].values()
                     if (symbol.section is not None
                         and '.export.' in symbol.section.name
                         and symbol.name != symbol.section.name)]
    li.varlowsyms = [symbol for symbol in info32flat[1].values()
                     if (symbol.section is not None
                         and symbol.section.finalloc is not None
                         and '.data.varlow.' in symbol.section.name
                         and symbol.name != symbol.section.name)]

    # Write out linker script files.
    writeLinkerScripts(li, out16, out32seg, out32flat)

if __name__ == '__main__':
    main()
