import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Secure temporary files.
 *
 * CodeQL's js/insecure-temporary-file fires on writing to a predictable path
 * inside a shared directory: anything else on the device can pre-create that
 * name as a symlink, and the write lands wherever the attacker pointed it. On a
 * phone that shared directory is /data/data/com.termux/files/usr/tmp, and the
 * payload in these routes is a database backup - credentials included.
 *
 * The fix is not a random suffix on a predictable name, because a race can still
 * win between the name check and the open. The fix is a private directory with
 * mode 0700 created by mkdtemp, which is atomic: the directory either does not
 * exist or belongs to us.
 */

const created: string[] = [];

/** A private temp directory, mode 0700, unique per call. */
export function secureTempDir(prefix = "omniroute-"): string {
  const base = os.tmpdir();
  // mkdtemp is atomic and refuses to reuse an existing path, which is the whole
  // point. 0o700 keeps other apps and other Termux sessions out.
  const dir = fs.mkdtempSync(path.join(base, prefix));
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // Already 0700 on most platforms; a failure here is not worth failing a
    // request over, and the directory is still unique.
  }
  created.push(dir);
  return dir;
}

/**
 * A path for a new temp file inside a private directory.
 *
 * Use this instead of path.join(os.tmpdir(), someName). The file itself is 0600
 * because a database backup should not be world-readable even inside a private
 * directory.
 */
export function secureTempFile(filename: string, prefix?: string): string {
  const dir = secureTempDir(prefix);
  const safe = path.basename(filename).replace(/[^A-Za-z0-9._-]/g, "_");
  const p = path.join(dir, safe);
  return p;
}

/** Remove a directory created by secureTempDir, ignoring anything already gone. */
export function removeSecureTempDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    // Best effort; the OS reclaims tmp on reboot.
  }
  const i = created.indexOf(dir);
  if (i >= 0) created.splice(i, 1);
}

/** Test seam: a name that cannot collide, for callers that need it in a message. */
export function uniqueSuffix(): string {
  return randomBytes(8).toString("hex");
}
