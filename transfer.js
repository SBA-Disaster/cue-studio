/* Cue Studio · Script transfer (QR code and iPad link)
   Moves a script from one device to another without files, servers, or copy and paste on the receiving device.
   Payload: JSON {v,t,x} → UTF-8 → deflate-raw (if available) → optional AES-GCM with a PBKDF2 passcode key → base64url.
   Frames: CUE1.<id>.<part>.<total>.<chunk>, carried in a URL fragment (#import=...) so the text is never sent to the web server. */
(() => {
  'use strict';
  const PREFIX = 'CUE1';
  const QR_CHUNK = 480;      // characters of payload per QR frame (keeps codes easy to read from a screen)
  const QR_SINGLE = 900;     // short scripts fit in one slightly denser, still-readable code
  const LINK_CHUNK = 6000;   // characters of payload per link
  const MAILTO_MAX = 1800;   // longer links are unreliable in mailto drafts
  const PENDING_KEY = 'cue-studio.transfer-pending';
  const PENDING_TTL = 24 * 60 * 60 * 1000;
  const T = { anim: null, scanStream: null, scanTimer: null, facing: 'environment', parts: null };

  /* ---------- encoding ---------- */
  const b64u = {
    enc(bytes) { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
    dec(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; const b = atob(str), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  };
  async function pipe(bytes, stream) { return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer()); }
  async function deriveKey(pass, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function pack(script, pass) {
    let bytes = new TextEncoder().encode(JSON.stringify({ v: 1, t: script.title, x: script.text })), flags = 0;
    if (window.CompressionStream) { bytes = await pipe(bytes, new CompressionStream('deflate-raw')); flags |= 1; }
    if (pass) {
      if (!crypto?.subtle) throw Error('Passcodes need a secure (https) page.');
      const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
      const c = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await deriveKey(pass, salt), bytes));
      const out = new Uint8Array(28 + c.length); out.set(salt); out.set(iv, 16); out.set(c, 28); bytes = out; flags |= 2;
    }
    const out = new Uint8Array(bytes.length + 1); out[0] = flags; out.set(bytes, 1); return b64u.enc(out);
  }
  async function unpack(payload, pass) {
    let all; try { all = b64u.dec(payload); } catch (e) { throw Error('This transfer is damaged. Send it again.'); }
    const flags = all[0]; let bytes = all.subarray(1);
    if (flags & 2) {
      if (!pass) throw Object.assign(Error('Enter the passcode to open this script.'), { needPass: true });
      try { bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(16, 28) }, await deriveKey(pass, bytes.subarray(0, 16)), bytes.subarray(28))); }
      catch (e) { throw Object.assign(Error('That passcode is not correct.'), { needPass: true }); }
    }
    if (flags & 1) {
      if (!window.DecompressionStream) throw Error('This browser is too old to open the script. Update iPadOS, then try again.');
      try { bytes = await pipe(bytes, new DecompressionStream('deflate-raw')); } catch (e) { throw Error('This transfer is damaged. Send it again.'); }
    }
    let o; try { o = JSON.parse(new TextDecoder().decode(bytes)); } catch (e) { throw Error('This is not a Cue Studio script.'); }
    if (typeof o?.x !== 'string') throw Error('This is not a Cue Studio script.');
    return { title: String(o.t || 'Transferred script').slice(0, 160), text: o.x };
  }
  function makeFrames(payload, size) {
    const id = Math.random().toString(36).slice(2, 8).padEnd(6, '0'), n = Math.max(1, Math.ceil(payload.length / size)), out = [];
    for (let i = 0; i < n; i++) out.push(`${PREFIX}.${id}.${i + 1}.${n}.${payload.slice(i * size, (i + 1) * size)}`);
    return out;
  }
  const appUrl = () => location.origin + location.pathname;
  const linkFor = frame => appUrl() + '#import=' + frame;
  function parseFrame(str) {
    const m = String(str || '').match(/(CUE1\.[a-z0-9]{1,12}\.\d{1,4}\.\d{1,4}\.[A-Za-z0-9_-]+)/);
    if (!m) return null;
    const [, id, i, n, chunk] = m[1].split('.');
    const fi = +i, fn = +n;
    if (!(fn >= 1 && fn <= 999 && fi >= 1 && fi <= fn)) return null;
    return { id, i: fi, n: fn, chunk };
  }

  /* ---------- dialog helpers ---------- */
  const dlg = () => document.getElementById('dialog');
  function view(title, html) {
    cleanup();
    if (dlg().open) { $('#dialog-title').textContent = title; $('#dialog-body').innerHTML = html; $('#dialog-error').textContent = ''; }
    else modal(title, html);
    bindClose();
  }
  const err = msg => { $('#dialog-error').textContent = msg || ''; };
  function cleanup() {
    if (T.anim) { clearInterval(T.anim); T.anim = null; }
    stopScan();
  }
  dlg().addEventListener('close', cleanup);
  const words = t => (t.trim().match(/\S+/g) || []).length;
  const fmtMin = t => { const m = Math.max(1, Math.round(words(t) / (data.settings.wpm || 140))); return m + ' min read'; };

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) {
      const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
      let ok = false; try { ok = document.execCommand('copy'); } catch (_) {} ta.remove(); return ok;
    }
  }

  /* ---------- home ---------- */
  function openTransfer() {
    const s = selected();
    const keep = s?.temp && canEdit() ? `<div class="notice tx-keep"><strong>${esc(s.title)}</strong> is session only and will be erased when Cue closes.<div class="dialog-actions" style="margin-top:10px"><button type="button" class="ghost" id="tx-keep">Keep in library</button></div></div>` : '';
    view('Transfer a script', `${keep}<div class="tx-choices"><button type="button" class="tx-choice" id="tx-send"><strong>Send a script</strong><span>Use on the computer that has the script. Shows a QR code or makes a link.</span></button><button type="button" class="tx-choice" id="tx-receive"><strong>Receive a script</strong><span>Use on the iPad. Scan the QR code shown on the computer screen.</span></button></div><p class="small muted">Nothing is uploaded. The script moves straight from one screen to the other, or inside a link you send through SBA email or Teams.</p>`);
    $('#tx-send').onclick = sendForm;
    $('#tx-receive').onclick = receiveView;
    if ($('#tx-keep')) $('#tx-keep').onclick = () => { delete s.temp; log('Kept session script: ' + s.title); persist(); closeModal(); render(); toast('Saved to your library.'); };
  }

  /* ---------- send ---------- */
  function sendForm() {
    if (!data.scripts.length) { err('Create or import a script first.'); return; }
    const cur = selected()?.id;
    const opts = data.scripts.map(s => `<option value="${esc(s.id)}" ${s.id === cur ? 'selected' : ''}>${esc(s.title)}</option>`).join('');
    view('Send a script', `<div class="field"><label for="tx-script">Script</label><select id="tx-script">${opts}</select><p class="small muted" id="tx-size" style="margin-top:6px"></p></div><div class="field"><label for="tx-pass">Passcode (optional)</label><input id="tx-pass" type="text" inputmode="text" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="64" placeholder="For example: blue-river-42"><p class="small muted" style="margin-top:6px">Locks the script so only someone with the passcode can open it. Share the passcode in person or by phone, not in the same message as the link.</p></div><div class="dialog-actions"><button type="button" class="ghost" id="tx-back">Back</button><button type="button" class="ghost" id="tx-link">Create link</button><button type="button" class="primary" id="tx-qr">Show QR code</button></div>`);
    const size = () => { const s = data.scripts.find(x => x.id === $('#tx-script').value); if (s) $('#tx-size').textContent = words(s.text).toLocaleString() + ' words · ' + fmtMin(s.text); };
    $('#tx-script').onchange = size; size();
    $('#tx-back').onclick = openTransfer;
    const go = async kind => {
      const s = data.scripts.find(x => x.id === $('#tx-script').value), pass = $('#tx-pass').value.trim();
      if (!s?.text.trim()) { err('That script is empty.'); return; }
      if (pass && pass.length < 4) { err('Use a passcode of at least 4 characters, or leave it blank.'); return; }
      err(''); $$('#dialog-body button').forEach(b => b.disabled = true);
      try { const payload = await pack(s, pass); log('Prepared transfer (' + kind + '): ' + s.title); kind === 'qr' ? qrView(s, payload, !!pass) : linkView(s, payload, !!pass); }
      catch (e) { $$('#dialog-body button').forEach(b => b.disabled = false); err('Could not prepare the transfer: ' + e.message); }
    };
    $('#tx-qr').onclick = () => go('qr');
    $('#tx-link').onclick = () => go('link');
  }

  function drawQR(canvas, text) {
    const qr = qrcode(0, 'L'); qr.addData(text, 'Byte'); qr.make();
    const n = qr.getModuleCount(), quiet = 4, total = n + quiet * 2, cell = Math.max(4, Math.floor(720 / total)), px = total * cell;
    canvas.width = canvas.height = px;
    const c = canvas.getContext('2d'); c.fillStyle = '#fff'; c.fillRect(0, 0, px, px); c.fillStyle = '#000';
    for (let r = 0; r < n; r++) for (let k = 0; k < n; k++) if (qr.isDark(r, k)) c.fillRect((k + quiet) * cell, (r + quiet) * cell, cell, cell);
  }

  function qrView(s, payload, locked) {
    if (typeof qrcode !== 'function') { err('The QR code tool did not load. Reload the page and try again.'); return; }
    const frames = makeFrames(payload, payload.length <= QR_SINGLE ? QR_SINGLE : QR_CHUNK).map(linkFor), n = frames.length;
    view('Scan with the iPad', `<p class="small muted" style="margin:0 0 10px">On the iPad: open Cue Studio › Transfer › Receive a script, then point the camera at this code.${n > 1 ? ' The code changes every moment. Keep the camera on it until every part is checked off.' : ''}</p><div class="tx-qr-wrap"><canvas id="tx-canvas" aria-label="QR code for ${esc(s.title)}"></canvas></div><div class="row between tx-qr-bar"><span class="small"><strong>${esc(s.title)}</strong>${locked ? ' · Locked with passcode' : ''}</span><span class="small" id="tx-part">${n > 1 ? 'Part 1 of ' + n : 'Single code'}</span></div>${n > 1 ? `<div class="row tx-speed"><span class="small muted">Speed</span><div class="segmented" id="tx-speed"><button type="button" data-ms="700">Slow</button><button type="button" data-ms="400" class="selected">Normal</button><button type="button" data-ms="250">Fast</button></div><button type="button" class="ghost" id="tx-pause">Pause</button></div>` : ''}<div class="dialog-actions"><button type="button" class="ghost" id="tx-back">Back</button><button type="button" class="primary" data-close>Done</button></div>`);
    const canvas = $('#tx-canvas');
    let i = 0, ms = 400, paused = false;
    const show = () => { drawQR(canvas, frames[i]); if (n > 1) $('#tx-part').textContent = 'Part ' + (i + 1) + ' of ' + n; };
    const run = () => { if (T.anim) clearInterval(T.anim); T.anim = n > 1 && !paused ? setInterval(() => { i = (i + 1) % n; show(); }, ms) : null; };
    show(); run();
    $$('#tx-speed button').forEach(b => b.onclick = () => { ms = +b.dataset.ms; $$('#tx-speed button').forEach(x => x.classList.toggle('selected', x === b)); run(); });
    if ($('#tx-pause')) $('#tx-pause').onclick = e => { paused = !paused; e.target.textContent = paused ? 'Resume' : 'Pause'; run(); };
    $('#tx-back').onclick = sendForm;
  }

  function linkView(s, payload, locked) {
    const links = makeFrames(payload, LINK_CHUNK).map(linkFor), n = links.length;
    const subject = 'Cue script: ' + s.title;
    const rows = links.map((l, k) => `<div class="tx-link"><div class="row between"><strong class="small">${n > 1 ? 'Part ' + (k + 1) + ' of ' + n : 'iPad link'}</strong><span class="small muted">${l.length.toLocaleString()} characters</span></div><textarea readonly rows="${n > 1 ? 2 : 4}" aria-label="Link ${k + 1}">${esc(l)}</textarea><div class="dialog-actions" style="margin-top:6px"><button type="button" class="ghost" data-copy="${k}">Copy${n > 1 ? ' part ' + (k + 1) : ' link'}</button>${l.length <= MAILTO_MAX ? `<button type="button" class="ghost" data-mail="${k}">Email${n > 1 ? ' part ' + (k + 1) : ''}</button>` : ''}</div></div>`).join('');
    view('Send the iPad link', `<p class="small muted" style="margin:0 0 10px">Copy the link into an SBA Outlook or Teams message to the account used on the iPad, then tap it on the iPad.${n > 1 ? ' This script needs ' + n + ' links; tap each one, in any order, and Cue rejoins them.' : ''}${locked ? ' The script is locked; the iPad will ask for the passcode.' : ''}</p>${rows}<div class="notice small" style="margin:12px 0 0">Links open in the iPad's browser. If you use Cue from the Home Screen icon, the script will appear in the browser version instead. Use the QR code to send straight to the Home Screen app.</div><div class="dialog-actions"><button type="button" class="ghost" id="tx-back">Back</button><button type="button" class="primary" data-close>Done</button></div>`);
    $$('[data-copy]').forEach(b => b.onclick = async () => { const ok = await copyText(links[+b.dataset.copy]); b.textContent = ok ? 'Copied' : 'Select and copy'; if (!ok) b.closest('.tx-link').querySelector('textarea').select(); });
    $$('[data-mail]').forEach(b => b.onclick = () => { const k = +b.dataset.mail; location.href = 'mailto:?subject=' + encodeURIComponent(subject + (n > 1 ? ' (part ' + (k + 1) + ' of ' + n + ')' : '')) + '&body=' + encodeURIComponent('Tap on the iPad to open in Cue Studio:\n\n' + links[k] + '\n'); });
    $$('.tx-link textarea').forEach(t => t.onfocus = () => t.select());
    $('#tx-back').onclick = sendForm;
  }

  /* ---------- receive (QR) ---------- */
  function receiveView() {
    const scanReady = typeof jsQR === 'function';
    view('Receive a script', `<div class="tx-scan" id="tx-scan"><video id="tx-video" playsinline muted autoplay></video><div class="tx-scan-frame" aria-hidden="true"></div><div class="tx-scan-msg" id="tx-scan-msg">Starting camera…</div></div><div class="tx-progress" id="tx-progress" aria-live="polite"></div><p class="small muted" id="tx-scan-tip">Point the camera at the QR code on the computer screen. Hold steady about 1 to 2 feet away and turn up screen brightness if it struggles.</p><p class="small muted">Received a link instead? Tap it in Outlook or Teams on this iPad.</p><div class="dialog-actions"><button type="button" class="ghost" id="tx-back">Back</button><button type="button" class="ghost" id="tx-flip">Switch camera</button></div>`);
    $('#tx-back').onclick = openTransfer;
    $('#tx-flip').onclick = () => { T.facing = T.facing === 'environment' ? 'user' : 'environment'; startScan(); };
    T.parts = null;
    if (!scanReady) { $('#tx-scan-msg').textContent = 'The QR reader did not load. Reload the page and try again.'; return; }
    startScan();
  }
  function stopScan() {
    if (T.scanTimer) { clearTimeout(T.scanTimer); T.scanTimer = null; }
    if (T.scanStream) { T.scanStream.getTracks().forEach(t => t.stop()); T.scanStream = null; }
  }
  async function startScan() {
    stopScan();
    const msg = $('#tx-scan-msg');
    if (recorder?.state === 'recording') { msg.textContent = 'Stop recording before scanning.'; return; }
    if (!navigator.mediaDevices?.getUserMedia) { msg.textContent = 'This browser cannot use the camera here.'; return; }
    try {
      T.scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: T.facing }, width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
    } catch (e) { msg.textContent = 'Camera unavailable: ' + e.message; return; }
    const v = $('#tx-video'); if (!v) { stopScan(); return; }
    v.srcObject = T.scanStream; v.classList.toggle('mirror', T.facing === 'user');
    try { await v.play(); } catch (e) {}
    msg.textContent = 'Looking for a Cue QR code…';
    const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d', { willReadFrequently: true });
    const tick = () => {
      if (!T.scanStream || !document.getElementById('tx-video')) return;
      if (v.readyState >= 2 && v.videoWidth) {
        const scale = Math.min(1, 960 / v.videoWidth), w = Math.round(v.videoWidth * scale), h = Math.round(v.videoHeight * scale);
        canvas.width = w; canvas.height = h; ctx.drawImage(v, 0, 0, w, h);
        const code = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
        if (code?.data) {
          const f = parseFrame(code.data);
          if (!f) msg.textContent = 'That QR code is not from Cue Studio.';
          else if (addScanPart(f)) return;
        }
      }
      T.scanTimer = setTimeout(tick, 80);
    };
    tick();
  }
  function addScanPart(f) {
    if (!T.parts || T.parts.id !== f.id || T.parts.n !== f.n) T.parts = { id: f.id, n: f.n, got: {} };
    const fresh = !T.parts.got[f.i]; T.parts.got[f.i] = f.chunk;
    const have = Object.keys(T.parts.got).length;
    if (fresh && navigator.vibrate) navigator.vibrate(15);
    $('#tx-scan-msg').textContent = f.n > 1 ? `Received ${have} of ${f.n} parts` : 'Code received';
    $('#tx-progress').innerHTML = f.n > 1 ? Array.from({ length: f.n }, (_, k) => `<span class="${T.parts.got[k + 1] ? 'on' : ''}" title="Part ${k + 1}"></span>`).join('') : '';
    if (have === f.n) {
      const payload = Array.from({ length: f.n }, (_, k) => T.parts.got[k + 1]).join('');
      stopScan(); T.parts = null; finish(payload); return true;
    }
    return false;
  }

  /* ---------- receive (link) ---------- */
  function readPending() { try { const p = JSON.parse(localStorage.getItem(PENDING_KEY) || '{}'); const now = Date.now(); for (const k in p) if (!p[k] || now - p[k].at > PENDING_TTL) delete p[k]; return p; } catch (e) { return {}; } }
  function writePending(p) { try { Object.keys(p).length ? localStorage.setItem(PENDING_KEY, JSON.stringify(p)) : localStorage.removeItem(PENDING_KEY); } catch (e) {} }
  function handleHash() {
    if (!location.hash.startsWith('#import=')) return;
    const f = parseFrame(location.hash);
    history.replaceState(null, '', location.pathname + location.search);   // remove the script from the address bar and history entry
    if (!f) { toast('That link is incomplete. Ask for it to be sent again.'); return; }
    if (f.n === 1) { finish(f.chunk); return; }
    const p = readPending(); if (!p[f.id] || p[f.id].n !== f.n) p[f.id] = { n: f.n, at: Date.now(), got: {} };
    p[f.id].got[f.i] = f.chunk; p[f.id].at = Date.now();
    const got = p[f.id].got, have = Object.keys(got).length;
    if (have === f.n) { const payload = Array.from({ length: f.n }, (_, k) => got[k + 1]).join(''); delete p[f.id]; writePending(p); finish(payload); return; }
    writePending(p);
    const missing = Array.from({ length: f.n }, (_, k) => k + 1).filter(k => !got[k]);
    view('Part ' + f.i + ' of ' + f.n + ' received', `<p>${have} of ${f.n} parts are here. Go back to Outlook or Teams and tap ${missing.length === 1 ? 'part ' + missing[0] : 'parts ' + missing.join(', ')}.</p><div class="tx-progress">${Array.from({ length: f.n }, (_, k) => `<span class="${got[k + 1] ? 'on' : ''}"></span>`).join('')}</div><p class="small muted">Parts wait here for up to 24 hours, then are deleted.</p><div class="dialog-actions"><button type="button" class="ghost" id="tx-discard">Discard parts</button><button type="button" class="primary" data-close>OK</button></div>`);
    $('#tx-discard').onclick = () => { const q = readPending(); delete q[f.id]; writePending(q); closeModal(); toast('Parts discarded.'); };
  }

  /* ---------- finish: passcode, preview, save ---------- */
  async function finish(payload, pass) {
    let s;
    try { s = await unpack(payload, pass); }
    catch (e) {
      if (e.needPass) { passView(payload, pass ? e.message : ''); return; }
      view('Could not open the script', `<p>${esc(e.message)}</p><div class="dialog-actions"><button type="button" class="primary" data-close>OK</button></div>`); return;
    }
    const lines = s.text.trim().split(/\n+/).slice(0, 3).join('\n').slice(0, 280);
    view('Script received', `<p style="margin-top:0"><strong>${esc(s.title)}</strong></p><p class="small muted">${words(s.text).toLocaleString()} words · ${fmtMin(s.text)}</p><div class="notice tx-preview">${esc(lines)}${s.text.trim().length > lines.length ? '…' : ''}</div><p class="small muted">Session only keeps the script in memory and erases it when Cue closes. Add to library saves it on this device.</p><div class="dialog-actions"><button type="button" class="ghost" data-close>Discard</button><button type="button" class="ghost" id="tx-temp">Session only</button>${canEdit() ? '<button type="button" class="primary" id="tx-save">Add to library</button>' : ''}</div>`);
    const add = temp => {
      const sc = { id: uid(), title: s.title, text: s.text, folder: temp ? null : (typeof folder === 'string' ? folder : null), versions: [], updated: Date.now(), owner: user().id };
      if (temp) sc.temp = true;
      data.scripts.push(sc); log((temp ? 'Received script (session only): ' : 'Received script: ') + sc.title);
      closeModal(); loadScript(sc.id); toast(temp ? 'Ready for this session. It will be erased when Cue closes.' : 'Added to your library.');
    };
    $('#tx-temp').onclick = () => add(true);
    if ($('#tx-save')) $('#tx-save').onclick = () => add(false);
  }
  function passView(payload, msg) {
    view('Enter the passcode', `<form id="tx-pass-form"><p style="margin-top:0">This script is locked. Type the passcode you were given.</p><div class="field"><label for="tx-pass-in">Passcode</label><input id="tx-pass-in" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="64" required></div><div class="dialog-actions"><button type="button" class="ghost" data-close>Cancel</button><button class="primary">Unlock</button></div></form>`);
    err(msg);
    const inp = $('#tx-pass-in'); setTimeout(() => inp.focus(), 50);
    $('#tx-pass-form').onsubmit = async e => { e.preventDefault(); const b = $('#tx-pass-form .primary'); b.disabled = true; b.textContent = 'Unlocking…'; await finish(payload, inp.value.trim()); };
  }

  /* ---------- styles ---------- */
  const css = document.createElement('style');
  css.textContent = `.tx-choices{display:grid;gap:10px;margin-bottom:14px}.tx-choice{display:flex;flex-direction:column;align-items:flex-start;gap:4px;text-align:left;padding:16px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);width:100%;min-height:0;height:auto;white-space:normal}.tx-choice:hover{border-color:var(--accent,#e8b878)}.tx-choice span{font-size:13px;color:var(--muted);font-weight:400}.tx-keep{margin:0 0 14px}.tx-qr-wrap{background:#fff;border-radius:10px;padding:8px;display:flex;justify-content:center}.tx-qr-wrap canvas{width:min(420px,100%,calc(88dvh - 290px));height:auto;aspect-ratio:1;image-rendering:pixelated;display:block}.tx-qr-bar{margin-top:10px;gap:8px}.tx-speed{margin-top:10px;gap:10px;align-items:center}.tx-speed .segmented{flex:1}.tx-link{margin-bottom:12px}.tx-link textarea{width:100%;margin-top:6px;font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all;resize:vertical}.tx-scan{position:relative;background:#000;border-radius:10px;overflow:hidden;aspect-ratio:4/3;max-height:52dvh;margin:0 auto}.tx-scan video{width:100%;height:100%;object-fit:cover;display:block}.tx-scan video.mirror{transform:scaleX(-1)}.tx-scan-frame{position:absolute;inset:14% 22%;border:3px solid rgba(255,255,255,.85);border-radius:12px;box-shadow:0 0 0 999px rgba(0,0,0,.25)}.tx-scan-msg{position:absolute;left:0;right:0;bottom:0;padding:8px 12px;background:rgba(0,0,0,.65);color:#fff;font-size:13px;text-align:center}.tx-progress{display:flex;flex-wrap:wrap;gap:4px;margin:10px 0}.tx-progress span{width:14px;height:8px;border-radius:2px;background:var(--line)}.tx-progress span.on{background:#4fd1a5}.tx-preview{white-space:pre-wrap;margin:12px 0;font-size:14px;color:var(--text)}`;
  document.head.appendChild(css);

  window.openTransfer = openTransfer;
  window.cueTransfer = { pack, unpack, makeFrames, parseFrame, linkFor };   // exposed for testing
  window.addEventListener('hashchange', handleHash);
  if (!remoteRole) handleHash();
})();
