import re
import subprocess


def run_command(cmd):
    try:
        result = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.STDOUT,
            text=True
        )
        return result.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()


def run_command_argv(argv, input=None, timeout=30):
    """
    Run a command as an argv list with no shell involved.

    Use this instead of run_command() whenever any part of the command is
    built from a variable (password, filename, IP, ...), so that value can
    never be reinterpreted as shell syntax. `input`, if given, is written to
    the process's stdin — the safe replacement for shell pipes like
    `echo secret | some-tool --stdin`, which also leaves the secret out of
    the argv (and therefore out of `ps`).
    """
    try:
        result = subprocess.run(
            argv,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired as e:
        output = e.output
        return output.strip() if isinstance(output, str) else str(e)
    except OSError as e:
        return str(e)


def replace_in_file(path, pattern, replacement, count=0, flags=0):
    """
    Apply a regex substitution to a file in place — the shell-free
    replacement for `sed -i 's/pattern/replacement/' path`. Values used to
    build `pattern`/`replacement` (filenames, IPs, ...) are never handed to
    a shell or to sed, so they can't be reinterpreted as sed/shell syntax.

    `replacement` is applied via a callable so its content is used
    literally — a plain string passed to re.sub would let backslash
    sequences (e.g. "\\1") in a filename be reinterpreted as a group
    reference.
    """
    with open(path, "r") as f:
        content = f.read()
    new_content = re.sub(pattern, lambda _m: replacement, content, count=count, flags=flags)
    with open(path, "w") as f:
        f.write(new_content)
    return new_content
