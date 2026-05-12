import { dangerousExec } from './exec.js';
app.get('/run', (req, res) => dangerousExec(req.query.cmd));
