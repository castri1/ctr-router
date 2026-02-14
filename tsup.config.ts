import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'], // support both import and require
  dts: true, // generate types
  sourcemap: true,
  clean: true, // replaces rimraf
  target: 'es2022',
})
