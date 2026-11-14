import * as esbuild from 'esbuild';

console.log('[build] Bundling public/proof.js -> public/proof.bundle.js...');
await esbuild.build({
  entryPoints: ['public/proof.js'],
  bundle: true,
  outfile: 'public/proof.bundle.js',
  format: 'esm',
  target: ['es2022'],
  define: {
    'process.env.NODE_ENV': '"production"',
    'process.env': '{}',
    global: 'globalThis',
  },
});
console.log('[build] ✅ Bundle built successfully.');
