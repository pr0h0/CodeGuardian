import { exec } from 'node:child_process';
export function dangerousExec(cmd) {
  exec(cmd);
}
