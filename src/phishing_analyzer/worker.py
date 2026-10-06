"""One short-lived parser process, using pipes rather than temporary files."""
import json
import subprocess
import sys
import threading
from pathlib import Path
from . import config
from .parser import AnalysisError


def execute(command, raw, timeout, output_limit):
    try:
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             cwd=Path(__file__).resolve().parents[1], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError:
        raise AnalysisError("Analysis worker could not start.", 503) from None
    chunks, size = [], 0
    overflow = threading.Event()
    def read():
        nonlocal size
        while True:
            chunk = p.stdout.read(8192)
            if not chunk:
                break
            size += len(chunk)
            if size > output_limit:
                overflow.set()
                try:
                    p.kill()
                except OSError:
                    pass
                break
            chunks.append(chunk)
    def write():
        try:
            p.stdin.write(raw)
            p.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            p.stdin.close()
    reader = threading.Thread(target=read, daemon=True)
    writer = threading.Thread(target=write, daemon=True)
    reader.start(); writer.start()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()
        raise AnalysisError("Analysis timed out. Try a smaller or simpler email.", 503) from None
    finally:
        if p.poll() is None:
            p.kill(); p.wait()
        writer.join(); reader.join()
        p.stdout.close()
    if overflow.is_set() or p.returncode:
        raise AnalysisError("Analysis exceeded its output limit or could not complete.", 503)
    try:
        result = json.loads(b"".join(chunks))
    except (ValueError, UnicodeError):
        raise AnalysisError("Analysis worker returned an invalid response.", 503) from None
    if not isinstance(result, dict):
        raise AnalysisError("Analysis worker returned an invalid response.", 503)
    if "error" in result:
        raise AnalysisError(result["error"], result.get("status", 422))
    if not isinstance(result.get("report"), dict) or not isinstance(result.get("preview"), dict):
        raise AnalysisError("Analysis worker returned an invalid response.", 503)
    return result


def run_worker(raw, filename):
    return execute([sys.executable, "-B", "-m", "phishing_analyzer.worker", filename], raw, config.WORKER_TIMEOUT, config.OUTPUT_LIMIT)


def main():
    from .report import analyze
    try:
        raw = sys.stdin.buffer.read(config.RAW_LIMIT + 1)
        result = analyze(raw, sys.argv[1])
    except AnalysisError as e:
        result = {"error": str(e), "status": e.status}
    except Exception:
        result = {"error": "Email analysis could not complete safely.", "status": 422}
    payload = json.dumps(result, ensure_ascii=True).encode("utf-8")
    if len(payload) > config.OUTPUT_LIMIT:
        payload = b'{"error":"Report exceeds the output limit.","status":503}'
    sys.stdout.buffer.write(payload)


if __name__ == "__main__":
    main()
