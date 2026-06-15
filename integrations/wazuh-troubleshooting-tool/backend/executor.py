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
