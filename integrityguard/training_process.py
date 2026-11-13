"""Bounded child process for candidate training; never promotes a model."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def training_lock(data_root):
    path = Path(data_root) / 'online' / 'training.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def worker_main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-root', required=True, type=Path)
    parser.add_argument('--model', required=True, type=Path)
    parser.add_argument('--result', required=True, type=Path)
    parser.add_argument('--probe', action='store_true')
    args = parser.parse_args(argv)
    try:
        import torch
        from integrityguard.online_learn import build_candidate, candidate_readiness
        with training_lock(args.data_root):
            ready = candidate_readiness(args.data_root)
            info = {'torch': torch.__version__, 'cuda': torch.cuda.is_available(),
                    'cpu_threads': min(4, os.cpu_count() or 1), 'readiness': ready}
            candidate = None
            if not args.probe and ready['ready']:
                candidate = build_candidate(args.data_root, args.model, device='auto',
                                            cpu_threads=info['cpu_threads'])
            result = {'ok': True, 'runtime': info, 'candidate': candidate,
                      'status': 'probe' if args.probe else 'candidate_created' if candidate else 'insufficient_data'}
    except Exception as error:
        result = {'ok': False, 'error': f'{type(error).__name__}: {error}'}
    temporary = args.result.with_suffix('.tmp')
    temporary.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
    temporary.replace(args.result)
    return 0 if result['ok'] else 1


def worker_command():
    from .paths import APP_ROOT, FROZEN
    # Only the associated project checkout is considered, never incoming data
    # or arbitrary PATH interpreters. A standalone installation uses its EXE.
    project = APP_ROOT.parent.parent if FROZEN else APP_ROOT
    interpreter = project / '.venv' / 'Scripts' / 'python.exe'
    launcher = project / 'tools' / 'training_worker.py'
    if interpreter.is_file() and launcher.is_file() and (project / 'IntegrityGuard.pyw').is_file():
        return [str(interpreter), '-I', str(launcher)]
    if FROZEN:
        return [sys.executable, '--training-worker']
    return [sys.executable, '-I', str(APP_ROOT / 'tools' / 'training_worker.py')]


def run_training_process(data_root, model_path, *, probe=False, timeout=3600):
    data_root, model_path = Path(data_root).resolve(), Path(model_path).resolve()
    with tempfile.TemporaryDirectory(prefix='integrityguard-training-') as temp:
        result_path = Path(temp) / 'result.json'
        command = worker_command() + ['--data-root', str(data_root), '--model', str(model_path),
                                      '--result', str(result_path)]
        if probe:
            command.append('--probe')
        environment = os.environ.copy()
        bundle = getattr(sys, '_MEIPASS', None)
        if bundle and Path(command[0]).resolve() != Path(sys.executable).resolve():
            environment['PATH'] = os.pathsep.join(
                entry for entry in environment.get('PATH', '').split(os.pathsep)
                if entry and not Path(entry).resolve().is_relative_to(Path(bundle).resolve()))
        # Redirect to disk, not a pipe: no pipe deadlocks or unbounded RAM logs.
        with (Path(temp) / 'worker.log').open('wb') as log:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       cwd=temp, timeout=timeout, shell=False, env=environment,
                                       creationflags=0x08000000 if os.name == 'nt' else 0)
        if not result_path.is_file():
            raise RuntimeError(f'Процесс обучения не вернул результат (код {completed.returncode})')
        if result_path.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('Ответ процесса обучения превышает допустимый размер')
        result = json.loads(result_path.read_text(encoding='utf-8'))
        if completed.returncode != 0 or result.get('ok') is not True:
            raise RuntimeError(result.get('error', 'Ошибка процесса обучения'))
        return result
