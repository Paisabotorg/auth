// Polyfill WebSocket for Node.js < 22 before any ES modules load
const { WebSocket } = require('ws')
if (!global.WebSocket) global.WebSocket = WebSocket
