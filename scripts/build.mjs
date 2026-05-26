import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const isClangOnly = process.argv.includes('--clang-only');
const dockerCmd = process.platform === 'win32' ? 'docker.exe' : 'docker';
const candidateNodeModules = [
  path.join(root, 'node_modules'),
  path.resolve(root, '..', 'hash-wasm-cf', 'node_modules'),
];

function resolveToolBin(packageName, binaryPath) {
  for (const nodeModulesPath of candidateNodeModules) {
    const candidate = path.join(nodeModulesPath, ...binaryPath);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

const rollupBin = resolveToolBin('rollup', ['rollup', 'dist', 'bin', 'rollup']);
const tscBin = resolveToolBin('typescript', ['typescript', 'bin', 'tsc']);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    ...options,
  });

  if (result.status !== 0) {
    const code = result.status ?? 1;
    process.exit(code);
  }
}

function ensureClangImage() {
  const inspect = spawnSync(dockerCmd, ['images', '-q', 'clang:hash-wasm'], {
    encoding: 'utf8',
  });

  if (inspect.status !== 0) {
    process.exit(inspect.status ?? 1);
  }

  if ((inspect.stdout ?? '').trim() === '') {
    run(dockerCmd, ['build', '-f', 'scripts/Dockerfile', '-t', 'clang:hash-wasm', '.']);
  }
}

function toDockerVolumePath(filePath) {
  return filePath.replace(/\\/g, '/');
}

fs.rmSync(path.join(root, 'dist'), { recursive: true, force: true });
fs.mkdirSync(path.join(root, 'wasm'), { recursive: true });

ensureClangImage();

const volumePath = toDockerVolumePath(root);
const dockerArgs = [
  'run',
  '--rm',
  '-v', `${volumePath}:/app`,
];

if (process.platform !== 'win32' && typeof process.getuid === 'function' && typeof process.getgid === 'function') {
  dockerArgs.push('-u', `${process.getuid()}:${process.getgid()}`);
}

dockerArgs.push('clang:hash-wasm', 'bash', '-c', 'make -f /app/scripts/Makefile-clang --silent --always-make --output-sync=target -j8 all');
run(dockerCmd, dockerArgs);

if (isClangOnly) {
  process.exit(0);
}

run(process.execPath, ['scripts/make_json.js']);

if (rollupBin && fs.existsSync(rollupBin)) {
  run(process.execPath, [rollupBin, '-c']);
} else {
  throw new Error('Unable to locate rollup binary in local or sibling node_modules');
}

if (tscBin && fs.existsSync(tscBin)) {
  run(process.execPath, [
    tscBin,
    './lib/index',
    '--outDir',
    './dist',
    '--downlevelIteration',
    '--emitDeclarationOnly',
    '--declaration',
    '--resolveJsonModule',
    '--allowSyntheticDefaultImports',
  ]);
} else {
  throw new Error('Unable to locate tsc binary in local or sibling node_modules');
}