"""M4rkRecon - Subprocess runner with timeout, retry, and streaming output."""

import os
import subprocess
import shutil
from typing import Optional


def tool_exists(tool_path: str) -> bool:
    """Check if a tool binary exists and is executable."""
    if os.path.isfile(tool_path):
        return True
    return shutil.which(tool_path) is not None


def run_command(
    cmd: list[str],
    output_file: Optional[str] = None,
    timeout: int = 600,
    cwd: Optional[str] = None,
    stdin_data: Optional[str] = None,
) -> tuple[int, str, str]:
    """
    Run a command and return (returncode, stdout, stderr).
    Optionally write stdout to output_file.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            input=stdin_data,
        )
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if output_file and stdout:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(stdout)

        return proc.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def run_pipe(
    cmd1: list[str],
    cmd2: list[str],
    output_file: Optional[str] = None,
    timeout: int = 600,
) -> tuple[int, str, str]:
    """Run cmd1 | cmd2 pipeline."""
    try:
        p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p2 = subprocess.Popen(
            cmd2,
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        p1.stdout.close()
        stdout, stderr = p2.communicate(timeout=timeout)
        stdout = stdout.strip()

        if output_file and stdout:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(stdout)

        return p2.returncode, stdout, stderr.strip()

    except subprocess.TimeoutExpired:
        return -1, "", f"Pipeline timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, "", f"Tool not found: {e}"
    except Exception as e:
        return -1, "", str(e)


def run_python_module(
    module_cmd: list[str],
    output_file: Optional[str] = None,
    timeout: int = 600,
    cwd: Optional[str] = None,
) -> tuple[int, str, str]:
    """Run a Python-based tool (e.g., sqlmap, arjun, wafw00f)."""
    cmd = ["python3"] + module_cmd
    return run_command(cmd, output_file=output_file, timeout=timeout, cwd=cwd)
