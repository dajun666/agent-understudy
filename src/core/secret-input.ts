// Asking the person for a credential without the model, the host or a terminal transcript seeing it.
import { spawn, spawnSync } from 'node:child_process';

export type Scope = 'project' | 'session';
export interface Answer { value: string; scope: Scope }

/**
 * macOS: a native dialog with a hidden-answer field and the storage choice as its buttons.
 * The description goes in as an argument (never spliced into the script), so it can't inject AppleScript.
 */
export async function macDialog(name: string, description: string, project: string): Promise<Answer | undefined> {
  const script = `on run argv
  set r to display dialog (item 2 of argv) & return & return & "Project: " & (item 3 of argv) & return & return & "Commands get it as $AGENT_SECRET_" & (item 1 of argv) & ". The model only ever sees Hide(" & (item 1 of argv) & ")." with title ("agent-understudy: " & (item 1 of argv)) default answer "" with hidden answer buttons {"Cancel", "This session only", "Remember for this project"} default button 3 cancel button 1 with icon note
  return (button returned of r) & linefeed & (text returned of r)
end run`;
  // Async: the gateway keeps serving traffic while the dialog waits for the person.
  const out = await new Promise<string | undefined>((resolve) => {
    const p = spawn('osascript', ['-e', script, name, description || `${name} is needed for this project.`, project]);
    let stdout = '';
    p.stdout.on('data', (d) => { stdout += d; });
    const t = setTimeout(() => p.kill(), 600_000);
    p.on('close', (code) => { clearTimeout(t); resolve(code === 0 ? stdout : undefined); }); // Cancel, timeout, no GUI
  });
  if (out === undefined) return undefined;
  const nl = out.indexOf('\n');
  const button = out.slice(0, nl);
  const value = out.slice(nl + 1).replace(/\n$/, '');
  return { value, scope: button.startsWith('Remember') ? 'project' : 'session' };
}

export function hasGui(): boolean {
  if (process.platform !== 'darwin') return false;
  // An SSH session has no window server to draw a dialog on.
  return !process.env.SSH_CONNECTION && spawnSync('osascript', ['-e', 'return 1'], { timeout: 5000 }).status === 0;
}

export function openUrl(url: string) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).unref(); } catch { /* the URL is also returned to the caller */ }
}

/** Shell-quotes for POSIX sh. */
export const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
