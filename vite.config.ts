import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from "vite-plugin-singlefile"
import { ViteMinifyPlugin } from 'vite-plugin-minify'
import tailwindcss from '@tailwindcss/vite'
import fs from 'fs'
import path from 'path'



function stripCommentsPlugin() {
  return {
    name: 'strip-comments-plugin',
    closeBundle() {
      const filePath = path.resolve('dist/index.html');
      let content = fs.readFileSync(filePath, 'utf-8');

      content = content.replace(/\/\*[\s\S]*?\*\//g, ''); // Remove  comments /* ... */
      content = content.replace(/^\s*[\r\n]/gm, ''); // Remove blank lines
      content = content.replace(/[\r\n]+/g, ''); // Remove line breaks

      fs.writeFileSync(filePath, content);
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile(), ViteMinifyPlugin({}), stripCommentsPlugin()],
  server: {
    proxy: {
      '/ws': {
        target: 'http://localhost:3030',  // DEV server
        ws: true,
        changeOrigin: true
      }
    }
  },
  build: {
    minify: 'terser',
    terserOptions: {
      format: {
        comments: () => false,
      },
    },
  },
})
