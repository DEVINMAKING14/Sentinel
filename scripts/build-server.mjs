import { build } from 'esbuild';

await build({
  entryPoints: ['server-entry.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  packages: 'external',
  outfile: 'server.js',
  minify: true,
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
});
