import json

from django.test import TestCase

from dojo.models import Test
from dojo.tools.nsp.parser import NspParser


class TestFile(object):

    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestNspParser(TestCase):

    def test_parse_no_content_no_findings(self):
        results = self.NspParser(None,Test())
        self.assertEqual(0, len(results))

    def test_parse_single_low_finding(self):
        singlel_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:3.6
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(singlel_finding,Test())
        self.assertEqual(1, len(results))

    def test_parse_single_mediem_finding(self):
        singlem_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:4.5
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(singlem_finding,Test())
        self.assertEqual(1, len(results))

    def test_parse_single_high_finding(self):
        singleh_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:7.5
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(singleh_finding,Test())
        self.assertEqual(1, len(results))

    def test_parse_single_critical_finding(self):
        singlec_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:9.6
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(singlec_finding,Test())
        self.assertEqual(1, len(results))

    def test_parse_multiple_finding(self):
        mul_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:3.6
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:5.5
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(mul_finding,Test())
        self.assertEqual(2, len(results))

    def test_parse_single_duplicated_finding(self):
        dup_finding = """<?xml version="1.0" encoding="utf-8"?>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:3.6
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>
        <Title>CVE-2018-20651-(NULL Pointer Dereference,cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*)</Title>
        <Description>A NULL pointer dereference was discovered in elf_link_add_object_symbols in 
        elflink.c in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU 
        Binutils 2.31.1. This occurs for a crafted ET_DYN with no program headers. A specially crafted 
        ELF file allows remote attackers to cause a denial of service, as demonstrated by ld.
        Vulnerable Module:NULL Pointer Dereference
        Vulnerable Versions:
        Current Version:cpe:2.3:a:gnu:binutils:2.31.1:*:*:*:*:*:*:*
        Patched Version:CPE 2.2
        Vulnerable Path:http://www.securityfocus.com/bid/106440>https://sourceware.org/bugzilla/show_bug.cgi?id=24041
        CVSS Score:3.6
        CVSS Vector:AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</Description>
        <recommendation>NIST does not necessarily endorse the views expressed, or concur with the facts presented on 
        these sites. Further, NIST does not endorse any commercial products that may be mentioned on these sites.</recommendation>
        <advisory>https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=54025d5812ff100f5f0654eb7e1ffd50f2e37f5f</advisory>"""

        results = self.NspParser(dup_finding,Test())
        self.assertEqual(1, len(results))

    def test_parse_no_assert_finding(self):
        self.assertIsNone(self.NspParser(None,Test()))

