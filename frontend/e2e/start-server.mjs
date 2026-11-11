import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const command = process.platform === 'win32'
  ? path.join(repo, '.venv', 'Scripts', 'python.exe')
  : path.join(repo, '.venv', 'bin', 'python');
const dataDir = process.env.CODESENTRY_E2E_DATA_DIR
  || path.join(repo, '.venv', `web-e2e-${process.pid}-${Date.now()}`);
// Every browser flow uses the same real app, with a test-only in-process model
// transport. Even an accidental provider fallback is disabled by the launcher.
const child = spawn(command, ['-I', path.join(repo, 'frontend', 'e2e', 'semantic-server.py'),
  '--data-dir', dataDir, '--frontend-dir', path.join(repo, 'frontend', 'dist')],
  { cwd: repo, stdio: 'inherit', shell: false, windowsHide: true });
child.on('error', (error) => { process.stderr.write(String(error)); process.exit(1); });
child.on('exit', (code) => process.exit(code ?? 1));
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => child.kill(signal));
}
