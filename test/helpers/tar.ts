export interface TarEntry {
  name: string;
  content?: Buffer | string;
  mode?: number;
  type?: 'file' | 'directory';
}

function header(name: string, size: number, mode: number, typeflag: string): Buffer {
  const buffer = Buffer.alloc(512);
  buffer.write(name.slice(0, 100), 0, 100, 'utf8');
  buffer.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'utf8');
  buffer.write('0000000\0', 108, 8, 'utf8');
  buffer.write('0000000\0', 116, 8, 'utf8');
  buffer.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');
  buffer.write('00000000000\0', 136, 12, 'utf8');
  buffer.write('        ', 148, 8, 'utf8');
  buffer.write(typeflag, 156, 1, 'utf8');
  buffer.write('ustar\0', 257, 6, 'utf8');
  buffer.write('00', 263, 2, 'utf8');
  buffer.write('root', 265, 32, 'utf8');
  buffer.write('root', 297, 32, 'utf8');

  let checksum = 0;
  for (const byte of buffer) checksum += byte;
  buffer.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');
  return buffer;
}

function pad(size: number): Buffer {
  const remainder = size % 512;
  return remainder === 0 ? Buffer.alloc(0) : Buffer.alloc(512 - remainder);
}

/** Minimal deterministic ustar writer, used only to build test images without a Docker daemon. */
export function createTar(entries: TarEntry[]): Buffer {
  const chunks: Buffer[] = [];
  for (const entry of entries) {
    const content = typeof entry.content === 'string' ? Buffer.from(entry.content, 'utf8') : (entry.content ?? Buffer.alloc(0));
    const isDirectory = entry.type === 'directory';
    const name = isDirectory && !entry.name.endsWith('/') ? `${entry.name}/` : entry.name;
    chunks.push(header(name, isDirectory ? 0 : content.length, entry.mode ?? (isDirectory ? 0o755 : 0o644), isDirectory ? '5' : '0'));
    if (!isDirectory) {
      chunks.push(content);
      chunks.push(pad(content.length));
    }
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}
