"""Record an explicitly disabled CI check without pretending it passed."""
import pathlib
import sys
import xml.etree.ElementTree as ET
name, reason = sys.argv[1:]
root = ET.Element("testsuite", name=name, tests="1", failures="0", skipped="1")
case = ET.SubElement(root, "testcase", name=name)
ET.SubElement(case, "skipped", message=reason)
pathlib.Path("reports").mkdir(exist_ok=True)
ET.ElementTree(root).write(f"reports/{name}.xml", encoding="unicode")
print(f"SKIPPED {name}: {reason}")
