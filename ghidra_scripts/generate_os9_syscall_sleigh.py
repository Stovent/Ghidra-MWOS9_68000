# Script that takes the json list of system calls and output ghidra sleigh specification.

from json import JSONDecoder
import sys

def is_noerror(syscall: dict[str, str]) -> bool:
    return "noerror" in syscall

def is_noreturn(syscall: dict[str, str]) -> bool:
    return "noreturn" in syscall

def make_pcode_name(name: str) -> str:
    return "os9_" + name.replace("$", "")

def make_input_pcode_args(inputs: list[str]) -> str:
    return ','.join(inputs)

def make_output_pcode_dict(name: str, outputs: list[dict[str, str]]) -> list[dict[str, str]]:
    pcode: list[dict[str, str]] = []

    for output in outputs:
        for key in output.keys():
            k = f"{name}_{key}"
            pcode.append({k: output[key]})

    return pcode

def make_output_pcode_defines(outputs: list[dict[str, str]]) -> str:
    defines: str = ""

    for output in outputs:
        for key in output.keys():
            defines += f"define pcodeop {key};\n"

    return defines

def make_output_pcode_assignments(outputs: list[dict[str, str]]) -> str:
    stores = ""

    for output in outputs:
        for key in output.keys():
            stores += f"    {output[key]} = {key}();\n"

    return stores

BODY: str = """
    CF = {pcode_name}({pcode_args});
    if (CF) goto <error>;
{pcode_assignments}
    goto inst_next;

    <error>
    D1w = os9_syscall_error();
"""

BODY_NOERROR: str = """
    {pcode_name}({pcode_args});
{pcode_assignments}
"""

BODY_NORETURN: str = """
    CF = {pcode_name}({pcode_args});
    if (CF) goto <error>;
    <loop>
    goto <loop>;
    <error>
    D1w = os9_syscall_error();
"""

BODY_NOERROR_NORETURN: str = """
    {pcode_name}({pcode_args});
{pcode_assignments}
    <loop>
    goto <loop>;
"""

def generate_sleigh(pcode: dict[str, str], noerror: bool, noreturn: bool) -> str:
    sleigh_format = """
{pcode_defines}
define pcodeop {pcode_name};
:{pcode_name} is op015=0x4E40 ; syscall={id} {{"""

    if noerror:
        if noreturn:
            sleigh_format += BODY_NOERROR_NORETURN
        else:
            sleigh_format += BODY_NOERROR
    else:
        if noreturn:
            sleigh_format += BODY_NORETURN
        else:
            sleigh_format += BODY

    sleigh_format += "}}\n"

    return sleigh_format.format(**pcode)

def generate_os9_syscall_sleigh(json_string: str) -> str:
    json_decoder = JSONDecoder()
    json = json_decoder.decode(json_string)

    sleigh: str = ""
    for syscall in json:
        print(syscall)
        pcode_name = make_pcode_name(syscall["name"])
        pcode_args = make_input_pcode_args(syscall["input"])

        outputs = make_output_pcode_dict(pcode_name, syscall["output"])
        pcode_defines = make_output_pcode_defines(outputs)
        pcode_assignments = make_output_pcode_assignments(outputs)

        pcode: dict[str, str] = {
            "id": syscall["id"],
            "name": syscall["name"],
            "pcode_name": pcode_name,
            "pcode_args": pcode_args,
            "pcode_defines": pcode_defines,
            "pcode_assignments": pcode_assignments
        }
        sleigh += generate_sleigh(pcode, is_noerror(syscall), is_noreturn(syscall))

    return sleigh

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input json file> <output file name>")
        exit(1)

    with open(sys.argv[1], "rt") as f:
        json = f.read()
        sleigh = generate_os9_syscall_sleigh(json)
        with open(sys.argv[2], "wt") as out:
            out.write(sleigh)
