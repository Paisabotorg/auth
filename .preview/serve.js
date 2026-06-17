import http from 'http'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const dir = path.dirname(fileURLToPath(import.meta.url))
const PORT = 3200

http.createServer((req, res) => {
  const file = path.join(dir, req.url === '/' ? 'language.html' : req.url)
  try {
    const data = fs.readFileSync(file)
    const ext = path.extname(file)
    const ct = ext === '.css' ? 'text/css' : ext === '.js' ? 'text/javascript' : 'text/html'
    res.writeHead(200, { 'Content-Type': ct + '; charset=utf-8' })
    res.end(data)
  } catch {
    res.writeHead(404); res.end('not found')
  }
}).listen(PORT, () => console.log(`preview on http://localhost:${PORT}`))
