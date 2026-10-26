/* Stego Image — LSB steganography in the R, G, B channels; optional AES-256-GCM (PBKDF2-SHA256, 600k).
   Layout of the hidden bytes:  "S3SG" | version 1 | flags (bit0 = encrypted) | length (uint32 BE) | payload
   Encrypted payload:           salt (16) | iv (12) | AES-GCM ciphertext + 16-byte tag, AAD = the first 6 header bytes. */
(function () {
  "use strict";
  var $ = S3.$, $$ = S3.$$;
  var MAGIC = [0x53, 0x33, 0x53, 0x47], VERSION = 1, HEAD = 10, ITER = 600000, SALT = 16, IV = 12, TAG = 16;
  var MAX_PIXELS = 50e6;
  var te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: true });
  var hasCrypto = !!(window.crypto && crypto.subtle && window.isSecureContext);

  // ---------- core (pure, works on RGBA byte arrays) ----------
  function capacity(w, h) { return Math.max(0, Math.floor(w * h * 3 / 8) - HEAD); }
  function overhead(encrypted) { return encrypted ? SALT + IV + TAG : 0; }

  function deriveKey(pw, salt) {
    return crypto.subtle.importKey("raw", te.encode(pw.normalize("NFC")), "PBKDF2", false, ["deriveKey"]).then(function (base) {
      return crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    });
  }
  function header(flags, len) {
    var h = new Uint8Array(HEAD); h.set(MAGIC); h[4] = VERSION; h[5] = flags;
    h[6] = len >>> 24 & 255; h[7] = len >>> 16 & 255; h[8] = len >>> 8 & 255; h[9] = len & 255;
    return h;
  }
  function concat(parts) {
    var n = parts.reduce(function (s, p) { return s + p.length; }, 0), o = new Uint8Array(n), off = 0;
    parts.forEach(function (p) { o.set(p, off); off += p.length; });
    return o;
  }
  // text (+ password) → bytes to hide
  function buildPayload(text, pw) {
    var plain = te.encode(text);
    if (!pw) return Promise.resolve(concat([header(0, plain.length), plain]));
    if (!hasCrypto) return Promise.reject(new Error("Encryption needs a secure (https) page"));
    var salt = crypto.getRandomValues(new Uint8Array(SALT)), iv = crypto.getRandomValues(new Uint8Array(IV));
    var len = SALT + IV + plain.length + TAG, h = header(1, len);
    return deriveKey(pw, salt).then(function (key) {
      return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: h.subarray(0, 6), tagLength: 128 }, key, plain);
    }).then(function (ct) { return concat([h, salt, iv, new Uint8Array(ct)]); });
  }
  // Write bytes MSB-first into the lowest bit of R, G, B (alpha untouched).
  function embed(px, w, h, bytes) {
    if (bytes.length - HEAD > capacity(w, h)) throw new Error("The message is too long for this image");
    for (var k = 0, bits = bytes.length * 8; k < bits; k++) {
      var bit = bytes[k >> 3] >> (7 - (k & 7)) & 1, idx = (k / 3 | 0) * 4 + k % 3;
      px[idx] = (px[idx] & 0xFE) | bit;
    }
    return px;
  }
  function readBytes(px, start, n) {
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) {
      var v = 0;
      for (var b = 0; b < 8; b++) { var k = (start + i) * 8 + b; v = v << 1 | px[(k / 3 | 0) * 4 + k % 3] & 1; }
      out[i] = v;
    }
    return out;
  }
  // → { flags, head, payload } or null when no message is present
  function extract(px, w, h) {
    if (w * h * 3 < HEAD * 8) return null;
    var hd = readBytes(px, 0, HEAD);
    for (var i = 0; i < 4; i++) if (hd[i] !== MAGIC[i]) return null;
    if (hd[4] !== VERSION) return { error: "This image was made by a newer version of the tool" };
    var len = (hd[6] << 24 | hd[7] << 16 | hd[8] << 8 | hd[9]) >>> 0;
    if (len > capacity(w, h)) return null;
    return { flags: hd[5], head: hd, payload: readBytes(px, HEAD, len) };
  }
  // → Promise<string>; rejects with code NEED_PASSWORD / WRONG_PASSWORD / CORRUPT
  function open(r, pw) {
    function fail(code, msg) { var e = new Error(msg); e.code = code; return Promise.reject(e); }
    if (!(r.flags & 1)) {
      try { return Promise.resolve(td.decode(r.payload)); } catch (e) { return fail("CORRUPT", "The hidden data is damaged"); }
    }
    if (!pw) return fail("NEED_PASSWORD", "This message is encrypted. Enter the password.");
    if (!hasCrypto) return fail("CORRUPT", "Decryption needs a secure (https) page");
    if (r.payload.length < SALT + IV + TAG) return fail("CORRUPT", "The hidden data is damaged");
    var salt = r.payload.slice(0, SALT), iv = r.payload.slice(SALT, SALT + IV), ct = r.payload.slice(SALT + IV);
    return deriveKey(pw, salt).then(function (key) {
      return crypto.subtle.decrypt({ name: "AES-GCM", iv: iv, additionalData: r.head.subarray(0, 6), tagLength: 128 }, key, ct);
    }).then(function (pt) {
      try { return td.decode(pt); } catch (e) { return fail("CORRUPT", "The hidden data is damaged"); }
    }, function () { return fail("WRONG_PASSWORD", "Wrong password, or the image was changed after hiding"); });
  }

  // ---------- image I/O ----------
  // Decode without colour management or premultiplication, so pixel values come back exactly as stored.
  function decode(file) {
    var opts = { premultiplyAlpha: "none", colorSpaceConversion: "none" };
    var p = window.createImageBitmap ? createImageBitmap(file, opts).catch(function () { return createImageBitmap(file); }) : Promise.reject();
    return p.catch(function () {
      return new Promise(function (res, rej) {
        var u = URL.createObjectURL(file), im = new Image();
        im.onload = function () { res(im); setTimeout(function () { URL.revokeObjectURL(u); }, 0); };
        im.onerror = function () { URL.revokeObjectURL(u); rej(new Error("Couldn't read that image")); };
        im.src = u;
      });
    });
  }
  function toCanvas(src, flatten) {
    var w = src.width || src.naturalWidth, h = src.height || src.naturalHeight;
    if (w * h > MAX_PIXELS) throw new Error("That image is too large (over 50 megapixels)");
    var c = document.createElement("canvas"); c.width = w; c.height = h;
    var x = c.getContext("2d", { willReadFrequently: true });
    if (flatten) { x.fillStyle = "#ffffff"; x.fillRect(0, 0, w, h); }
    x.drawImage(src, 0, 0);
    return c;
  }
  function pixels(c) { return c.getContext("2d", { willReadFrequently: true }).getImageData(0, 0, c.width, c.height); }
  function hasAlpha(img) { for (var i = 3; i < img.data.length; i += 4) if (img.data[i] !== 255) return true; return false; }
  function preview(target, c) {
    var k = Math.min(1, 900 / Math.max(c.width, c.height));
    target.width = Math.round(c.width * k); target.height = Math.round(c.height * k);
    var x = target.getContext("2d"); x.imageSmoothingQuality = "high"; x.drawImage(c, 0, 0, target.width, target.height);
  }
  function toPng(c) { return new Promise(function (res, rej) { c.toBlob(function (b) { b ? res(b) : rej(new Error("PNG encoding failed")); }, "image/png"); }); }

  // ---------- Hide ----------
  var cover = null; // { canvas, name, flattened }
  function setStatus(el, cls, text) { el.className = "chip " + cls; el.textContent = text; }
  function loadCover(file) {
    decode(file).then(function (src) {
      var c = toCanvas(src, false), flattened = false;
      if (hasAlpha(pixels(c))) { c = toCanvas(src, true); flattened = true; }
      cover = { canvas: c, name: (file.name || "image").replace(/\.[^.]+$/, ""), flattened: flattened };
      preview($("#hCv"), c);
      $("#hDrop").hidden = true; $("#hInfo").hidden = false; $("#hResult").hidden = true;
      $("#hMeta").textContent = c.width + " × " + c.height + " px" + (flattened ? " · transparency filled with white" : "");
      meter();
    }).catch(function (e) { S3.toast(e.message || "Couldn't read that image", "error"); });
  }
  function meter() {
    var cap = cover ? capacity(cover.canvas.width, cover.canvas.height) : 0;
    var used = te.encode($("#msg").value).length + overhead(!!$("#hPw").value);
    var pct = cap ? Math.min(100, used / cap * 100) : 0, fill = $("#meterFill");
    fill.style.width = (cover ? Math.max(pct, used ? 1 : 0) : 0) + "%";
    fill.className = used > cap ? "bad" : pct > 85 ? "warn" : "";
    $("#meter").setAttribute("aria-valuenow", Math.round(pct));
    $("#capLbl").textContent = cover ? S3.fmtBytes(used) + " of " + S3.fmtBytes(cap) + (used > cap ? " — too long" : "") : "Choose an image first";
    $("#hideBtn").disabled = !cover || !$("#msg").value || used > cap;
  }
  var hIn = S3.drop($("#hDrop"), function (fs) { loadCover(fs[0]); }, { accept: "image/*", multiple: false });
  $("#hNew").addEventListener("click", function () { hIn.click(); });
  $("#msg").addEventListener("input", meter);
  $("#hPw").addEventListener("input", meter);
  $("#hShow").addEventListener("click", function () { var p = $("#hPw"); p.type = p.type === "password" ? "text" : "password"; });
  if (!hasCrypto) { $("#hPw").disabled = true; $("#hPw").placeholder = "Passwords need the https version of this page"; }

  function hide() {
    var btn = $("#hideBtn"), res = $("#hResult"), pw = $("#hPw").value, text = $("#msg").value;
    btn.disabled = true; btn.lastChild.textContent = pw ? "Encrypting…" : "Hiding…";
    var out = document.createElement("canvas"), blob;
    out.width = cover.canvas.width; out.height = cover.canvas.height;
    return buildPayload(text, pw).then(function (bytes) {
      var img = pixels(cover.canvas);
      embed(img.data, img.width, img.height, bytes);
      out.getContext("2d").putImageData(img, 0, 0);
      return toPng(out);
    }).then(function (b) {
      blob = b;
      // Read our own PNG back the same way a receiver would, and make sure the message survives.
      return decode(b).then(function (src) { var p = pixels(toCanvas(src, false)); var r = extract(p.data, p.width, p.height); if (!r) throw new Error("VERIFY"); return open(r, pw); });
    }).then(function (back) {
      if (back !== text) throw new Error("VERIFY");
      var name = cover.name + "-hidden.png";
      S3.download(blob, name);
      res.hidden = false; res.className = "sg-result ok";
      res.textContent = "Saved " + name + " (" + S3.fmtBytes(blob.size) + "). Checked: the message reads back correctly" + (pw ? " with the password." : ".");
      S3.done();
    }).catch(function (e) {
      res.hidden = false; res.className = "sg-result bad";
      res.textContent = e.message === "VERIFY"
        ? "Your browser changed the image pixels while saving (a privacy feature in some browsers such as Brave or Safari private mode adds noise). Nothing was downloaded. Try another browser or turn the protection off for this page."
        : e.message;
    }).then(function () { btn.lastChild.textContent = "Hide message & download PNG"; meter(); });
  }
  $("#hideBtn").addEventListener("click", function () { if (cover) hide(); });

  // ---------- Reveal ----------
  var found = null;
  function loadReveal(file) {
    var st = $("#rStatus"); found = null;
    $("#out").value = ""; $("#copyOut").disabled = true; $("#rPwWrap").hidden = true;
    decode(file).then(function (src) {
      var c = toCanvas(src, false), p = pixels(c);
      preview($("#rCv"), c);
      $("#rDrop").hidden = true; $("#rInfo").hidden = false;
      $("#rMeta").textContent = (file.name || "image") + " · " + c.width + " × " + c.height + " px";
      var r = extract(p.data, p.width, p.height);
      if (!r) {
        setStatus(st, "bad", /jpe?g$/i.test(file.name || "") || file.type === "image/jpeg"
          ? "No message found. This is a JPEG: JPEG compression destroys hidden data."
          : "No hidden message found (or the image was recompressed, resized or edited).");
        return;
      }
      if (r.error) { setStatus(st, "bad", r.error); return; }
      found = r;
      if (r.flags & 1) { setStatus(st, "accent", "Encrypted message found. Enter the password."); $("#rPwWrap").hidden = false; $("#rPw").focus(); }
      else show();
    }).catch(function (e) { setStatus(st, "bad", e.message || "Couldn't read that image"); });
  }
  function show() {
    var st = $("#rStatus"), pw = $("#rPw").value;
    if (found.flags & 1) setStatus(st, "", "Checking password…");
    return open(found, pw).then(function (text) {
      $("#out").value = text; $("#copyOut").disabled = false;
      setStatus(st, "ok", (found.flags & 1 ? "Decrypted" : "Message found") + " · " + text.length.toLocaleString() + " characters");
      S3.done();
    }, function (e) { setStatus(st, "bad", e.message); if (e.code === "WRONG_PASSWORD") { $("#rPw").select(); } });
  }
  var rIn = S3.drop($("#rDrop"), function (fs) { loadReveal(fs[0]); }, { accept: "image/*", multiple: false });
  $("#rNew").addEventListener("click", function () { rIn.click(); });
  $("#unlock").addEventListener("click", function () { if (found) show(); });
  $("#rPw").addEventListener("keydown", function (e) { if (e.key === "Enter" && found) show(); });
  $("#copyOut").addEventListener("click", function () { S3.copy($("#out").value, "Message copied"); });

  $$("#mode button").forEach(function (b) {
    b.addEventListener("click", function () {
      $$("#mode button").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      $("#hide").hidden = b.dataset.v !== "hide"; $("#reveal").hidden = b.dataset.v !== "reveal";
    });
  });
  meter();

  // ---------- demo + selftest ----------
  function sampleCanvas() {
    var c = document.createElement("canvas"); c.width = 960; c.height = 640;
    var x = c.getContext("2d"), g = x.createLinearGradient(0, 0, 0, 640);
    g.addColorStop(0, "#1b2a49"); g.addColorStop(0.6, "#4b6cb7"); g.addColorStop(1, "#9fb8e8"); x.fillStyle = g; x.fillRect(0, 0, 960, 640);
    for (var i = 0; i < 140; i++) { x.fillStyle = "rgba(255,255,255," + (0.3 + (i * 37 % 70) / 100) + ")"; x.fillRect((i * 173) % 960, (i * 97) % 300, 2, 2); }
    x.fillStyle = "#f4f1de"; x.beginPath(); x.arc(700, 150, 60, 0, 7); x.fill();
    x.fillStyle = "#16213a"; x.beginPath(); x.moveTo(0, 640);
    for (var k = 0; k <= 960; k += 12) x.lineTo(k, 470 - Math.sin(k / 120) * 60 - Math.sin(k / 37) * 12);
    x.lineTo(960, 640); x.fill();
    return c;
  }
  window.S3_DEMO = function () {
    var c = sampleCanvas();
    cover = { canvas: c, name: "night", flattened: false };
    preview($("#hCv"), c); $("#hDrop").hidden = true; $("#hInfo").hidden = false;
    $("#hMeta").textContent = c.width + " × " + c.height + " px";
    $("#msg").value = "Meet at the old library at 7. Bring the blue notebook.";
    $("#hPw").value = "correct horse battery staple";
    meter();
  };

  window.S3_SELFTEST = async function () {
    var w = 48, h = 40, base = crypto.getRandomValues(new Uint8Array(w * h * 4));
    for (var i = 3; i < base.length; i += 4) base[i] = 255;
    var msg = "héllo 👋 مرحبا\nline two";
    // plain round trip; only LSBs of RGB may change
    var px = new Uint8ClampedArray(base);
    embed(px, w, h, await buildPayload(msg, ""));
    for (i = 0; i < px.length; i++) if (i % 4 === 3 ? px[i] !== base[i] : Math.abs(px[i] - base[i]) > 1) return "more than the LSB changed at " + i;
    var r = extract(px, w, h);
    if (!r || r.flags !== 0 || await open(r, "") !== msg) return "plain round trip failed";
    if (extract(new Uint8ClampedArray(base), w, h) !== null) return "found a message in random pixels";
    // encrypted round trip, wrong and missing password
    var ex = new Uint8ClampedArray(base);
    embed(ex, w, h, await buildPayload(msg, "s3cret pässword"));
    var r2 = extract(ex, w, h);
    if (!r2 || r2.flags !== 1 || r2.payload.length !== te.encode(msg).length + SALT + IV + TAG) return "encrypted header wrong";
    if (await open(r2, "s3cret pässword") !== msg) return "encrypted round trip failed (NFC password)";
    var code = "";
    try { await open(r2, "wrong"); } catch (e) { code = e.code; }
    if (code !== "WRONG_PASSWORD") return "wrong password not rejected";
    try { await open(r2, ""); code = ""; } catch (e) { code = e.code; }
    if (code !== "NEED_PASSWORD") return "missing password not detected";
    // a flipped bit in the ciphertext must fail authentication
    var tam = { flags: r2.flags, head: r2.head, payload: r2.payload.slice() }; tam.payload[tam.payload.length - 20] ^= 1;
    try { await open(tam, "s3cret pässword"); code = ""; } catch (e) { code = e.code; }
    if (code !== "WRONG_PASSWORD") return "tampering not detected";
    // capacity: 10×10 px → 300 bits → 37 bytes − 10 header = 27
    if (capacity(10, 10) !== 27) return "capacity wrong";
    var tooBig = false;
    try { embed(new Uint8ClampedArray(400), 10, 10, await buildPayload("x".repeat(28), "")); } catch (e) { tooBig = true; }
    if (!tooBig) return "oversize message accepted";
    // full browser path: canvas → PNG → decode → extract
    var c = document.createElement("canvas"); c.width = w; c.height = h;
    c.getContext("2d").putImageData(new ImageData(new Uint8ClampedArray(px), w, h), 0, 0);
    var back = await decode(await toPng(c)), bp = pixels(toCanvas(back, false)), r3 = extract(bp.data, bp.width, bp.height);
    if (!r3 || await open(r3, "") !== msg) return "PNG round trip failed";
    return true;
  };
})();
