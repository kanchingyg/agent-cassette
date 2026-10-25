import { isAbsolute, relative, resolve } from "node:path";

export function resolveCassettePath(input: string, cwd = process.cwd()): string {
  const base = resolve(cwd);
  const target = isAbsolute(input) ? resolve(input) : resolve(base, input);
  const rel = relative(base, target);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Cassette path must stay under ${base}`);
  }
  return target;
}
