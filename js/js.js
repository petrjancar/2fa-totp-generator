(() => {
  const $ = (id) => document.getElementById(id);
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const HASH = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

  function base32Encode(bytes) {
    let bits = 0,
      value = 0,
      out = "";
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out;
  }

  const randomSecret = (byteLen) =>
    base32Encode(crypto.getRandomValues(new Uint8Array(byteLen)));

  const normalizeSecret = (s) =>
    s.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();

  function base32Decode(s) {
    let bits = 0,
      value = 0;
    const out = [];
    for (const c of s) {
      value = (value << 5) | B32.indexOf(c);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  async function hotp(keyBytes, counter, algorithm, digits) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 2 ** 32));
    view.setUint32(4, counter >>> 0);
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: HASH[algorithm] },
      false,
      ["sign"],
    );
    const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
    const o = h[h.length - 1] & 0x0f;
    const bin =
      ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    return String(bin % 10 ** digits).padStart(digits, "0");
  }

  function readConfig() {
    const secret = normalizeSecret($("secret").value);
    const period = Number($("period").value);
    if (!secret) return { error: "Secret is required." };
    if (!/^[A-Z2-7]+$/.test(secret))
      return { error: "Secret must be Base32 (A-Z, 2-7)." };
    if (secret.length < 2) return { error: "Secret is too short." };
    if (!Number.isInteger(period) || period < 1 || period > 86400)
      return { error: "Period must be a whole number from 1 to 86400." };
    return {
      secret,
      period,
      account: $("account").value.trim(),
      issuer: $("issuer").value.trim(),
      algorithm: $("algorithm").value,
      digits: Number($("digits").value),
    };
  }

  function buildUri(c) {
    const issuer = encodeURIComponent(c.issuer);
    const label = [c.issuer, c.account]
      .filter(Boolean)
      .map(encodeURIComponent)
      .join(":");
    return (
      `otpauth://totp/${label}?secret=${c.secret}` +
      (c.issuer ? `&issuer=${issuer}` : "") +
      `&algorithm=${c.algorithm}&digits=${c.digits}&period=${c.period}`
    );
  }

  function renderQr(text) {
    const qr = qrcode(0, "M");
    qr.addData(text, "Byte");
    qr.make();
    const n = qr.getModuleCount(),
      margin = 4,
      size = n + margin * 2;
    let path = "";
    for (let r = 0; r < n; r++)
      for (let c = 0; c < n; c++)
        if (qr.isDark(r, c)) path += `M${c + margin} ${r + margin}h1v1h-1z`;
    $("qr").innerHTML =
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">` +
      `<path d="${path}" fill="#000"/></svg>`;
  }

  function clearResult() {
    $("result").textContent = "";
    $("result").className = "";
  }

  const setText = (el, text) => {
    if (el.textContent !== text) el.textContent = text;
  };

  function setStale(stale) {
    $("qr").classList.toggle("stale", stale);
    $("uri").classList.toggle("stale", stale);
  }

  function update() {
    const c = readConfig();
    clearResult();
    $("token").maxLength = $("digits").value;
    $("token").placeholder = "12345678".slice(0, Number($("digits").value));
    if (c.error) {
      setText($("error"), c.error);
      setText($("warning"), "");
      setStale(true);
      return;
    }
    setText($("error"), "");
    const secretBits = Math.floor((c.secret.length * 5) / 8) * 8;
    setText(
      $("warning"),
      secretBits < 128
        ? `Secret is only ${secretBits} bits; RFC 4226 requires at least 128 bits.`
        : "",
    );
    const uri = buildUri(c);
    $("uri").textContent = uri;
    setStale(false);
    try {
      renderQr(uri);
    } catch (e) {
      setStale(true);
      setText($("error"), "Could not render QR code: " + e.message);
    }
  }

  async function verify(e) {
    e.preventDefault();
    const c = readConfig();
    const out = $("result");
    const show = (text, cls) => {
      out.textContent = text;
      out.className = cls;
    };
    if (c.error) return show(c.error, "invalid");
    const token = $("token").value.trim();
    if (!new RegExp(`^\\d{${c.digits}}$`).test(token))
      return show(`Invalid: enter a ${c.digits}-digit token.`, "invalid");
    if (!crypto.subtle)
      return show(
        "Web Crypto unavailable (needs HTTPS or localhost).",
        "invalid",
      );

    const winText = $("window").value.trim();
    const win = Number(winText);
    if (winText === "" || !Number.isInteger(win) || win < 0 || win > 10)
      return show("Window must be a whole number from 0 to 10.", "invalid");

    try {
      const key = base32Decode(c.secret);
      const step = Math.floor(Date.now() / 1000 / c.period);
      for (let d = -win; d <= win; d++) {
        if (
          step + d >= 0 &&
          token === (await hotp(key, step + d, c.algorithm, c.digits))
        )
          return show(
            d === 0
              ? "Valid"
              : `Valid (${Math.abs(d)} period${Math.abs(d) > 1 ? "s" : ""} ${d < 0 ? "ago" : "ahead"})`,
            "valid",
          );
      }
      show("Invalid / Expired", "invalid");
    } catch (err) {
      show("Verification failed: " + err.message, "invalid");
    }
  }

  let lastTokenKey = "";

  function refreshCurrentToken(c) {
    const out = $("currentToken");
    if (c.error || !crypto.subtle) {
      lastTokenKey = "";
      out.textContent = "\u2014";
      return;
    }
    const step = Math.floor(Date.now() / 1000 / c.period);
    const key = [c.secret, c.algorithm, c.digits, c.period, step].join("|");
    if (key === lastTokenKey) return;
    lastTokenKey = key;
    hotp(base32Decode(c.secret), step, c.algorithm, c.digits)
      .then((t) => {
        if (key === lastTokenKey) out.textContent = t;
      })
      .catch(() => {
        if (key === lastTokenKey) out.textContent = "\u2014";
      });
  }

  let lastTimerKey = "";

  function tick() {
    const c = readConfig();
    refreshCurrentToken(c);
    $("timer").style.visibility = c.error ? "hidden" : "";
    if (c.error) return;
    const remaining = c.period - ((Date.now() / 1000) % c.period);
    $("barFill").style.width = (remaining / c.period) * 100 + "%";
    $("barFill").classList.toggle(
      "low",
      remaining <= Math.min(5, c.period / 4),
    );
    const secs = Math.ceil(remaining);
    const key = `${secs}/${c.period}`;
    if (key === lastTimerKey) return;
    lastTimerKey = key;
    $("timerText").textContent = `Next token in ${secs}s`;
    const bar = $("bar");
    bar.setAttribute("aria-valuemax", c.period);
    bar.setAttribute("aria-valuenow", secs);
    bar.setAttribute("aria-valuetext", `${secs} seconds remaining`);
  }

  const setMsg = (id, text, cls = "") => {
    $(id).textContent = text;
    $(id).className = "import-msg " + cls;
  };
  const importMsg = (text, cls) => setMsg("dlgMsg", text, cls);
  const importDone = (text, cls = "ok") => {
    stopCam();
    $("importDlg").close();
    setMsg("importMsg", text, cls);
  };

  function applyOtpauth(text) {
    let u;
    try {
      u = new URL(text.trim());
    } catch {
      throw new Error("QR code does not contain a valid URI.");
    }
    if (u.protocol === "otpauth-migration:")
      throw new Error(
        "Google Authenticator export QR codes are not supported.",
      );
    if (u.protocol !== "otpauth:" || u.hostname !== "totp")
      throw new Error("QR code is not an otpauth://totp URI.");
    const p = u.searchParams;
    const secret = normalizeSecret(p.get("secret") || "");
    if (!/^[A-Z2-7]+$/.test(secret))
      throw new Error("QR code has no valid Base32 secret.");
    let label = "";
    try {
      label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    } catch {}
    const i = label.indexOf(":");
    const issuer = p.get("issuer") || (i >= 0 ? label.slice(0, i).trim() : "");
    const account = (i >= 0 ? label.slice(i + 1) : label).trim();
    const algorithm = (p.get("algorithm") || "SHA1").toUpperCase();
    const digits = p.get("digits") || "6";
    const period = p.get("period") || "30";
    if (!HASH[algorithm])
      throw new Error(`QR code has unsupported algorithm "${algorithm}".`);
    if (digits !== "6" && digits !== "8")
      throw new Error(`QR code has unsupported digit count "${digits}".`);
    if (!/^\d+$/.test(period) || period < 1 || period > 86400)
      throw new Error("QR code has an invalid period.");

    $("secret").value = secret;
    $("account").value = account;
    $("issuer").value = issuer;
    $("algorithm").value = algorithm;
    $("digits").value = digits;
    $("period").value = period;
    update();
  }

  function decodeImageData(img) {
    const r = jsQR(img.data, img.width, img.height, {
      inversionAttempts: "attemptBoth",
    });
    return r ? r.data : null;
  }

  async function importFile(e) {
    const file = e.target.files[0];
    if (!file) return;
    importMsg("");
    try {
      stopCam();
      const bmp = await createImageBitmap(file);
      // Downscale very large images; jsQR is slow on huge inputs.
      const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
      const cv = document.createElement("canvas");
      cv.width = Math.round(bmp.width * scale);
      cv.height = Math.round(bmp.height * scale);
      const ctx = cv.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(bmp, 0, 0, cv.width, cv.height);
      bmp.close();
      const text = decodeImageData(ctx.getImageData(0, 0, cv.width, cv.height));
      if (!text) throw new Error("No QR code found in the image.");
      applyOtpauth(text);
      importDone("Imported from image.");
    } catch (err) {
      importDone(err.message || "Could not read the image.", "bad");
    } finally {
      e.target.value = "";
    }
  }

  let camStream = null;
  let camTimer = 0;
  const camCanvas = document.createElement("canvas");
  const camCtx = camCanvas.getContext("2d", { willReadFrequently: true });

  function stopCam() {
    clearInterval(camTimer);
    if (camStream) camStream.getTracks().forEach((t) => t.stop());
    camStream = null;
    $("cam").srcObject = null;
    $("camBox").hidden = true;
    $("scanCam").textContent = "Use webcam";
  }

  async function toggleCam() {
    if (camStream) {
      stopCam();
      importMsg("");
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia)
      return importMsg("Webcam unavailable (needs HTTPS or localhost).", "bad");
    try {
      $("scanCam").disabled = true;
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
      });
      // Dialog may have been closed while the permission prompt was open.
      if (!$("importDlg").open) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      camStream = stream;
    } catch (err) {
      return importMsg("Could not access webcam: " + err.message, "bad");
    } finally {
      $("scanCam").disabled = false;
    }
    const video = $("cam");
    video.srcObject = camStream;
    $("camBox").hidden = false;
    $("scanCam").textContent = "Stop webcam";
    importMsg("Point the QR code at the camera...");
    try {
      await video.play();
    } catch {}
    camTimer = setInterval(() => {
      if (!video.videoWidth) return;
      const scale = Math.min(1, 800 / video.videoWidth);
      camCanvas.width = Math.round(video.videoWidth * scale);
      camCanvas.height = Math.round(video.videoHeight * scale);
      camCtx.drawImage(video, 0, 0, camCanvas.width, camCanvas.height);
      const text = decodeImageData(
        camCtx.getImageData(0, 0, camCanvas.width, camCanvas.height),
      );
      if (!text) return;
      try {
        applyOtpauth(text);
        importDone("Imported from webcam.");
      } catch (err) {
        importDone(err.message, "bad");
      }
    }, 250);
  }

  $("qrFile").addEventListener("change", importFile);
  $("pickFile").addEventListener("click", () => $("qrFile").click());
  $("scanCam").addEventListener("click", toggleCam);
  $("openImport").addEventListener("click", () => {
    importMsg("");
    setMsg("importMsg", "");
    $("importDlg").showModal();
  });
  $("closeImport").addEventListener("click", () => $("importDlg").close());
  $("importDlg").addEventListener("close", stopCam);
  $("importDlg").addEventListener("click", (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    const inside =
      e.clientX >= r.left &&
      e.clientX <= r.right &&
      e.clientY >= r.top &&
      e.clientY <= r.bottom;
    if (!inside) e.currentTarget.close();
  });
  window.addEventListener("pagehide", stopCam);

  const newSecret = () => {
    $("secret").value = randomSecret(Number($("secretLen").value));
    update();
  };
  $("secret").value = randomSecret(Number($("secretLen").value));
  $("regen").addEventListener("click", newSecret);
  $("secretLen").addEventListener("change", () => {
    if (!$("secret").value.trim()) newSecret();
  });
  $("token").addEventListener("input", clearResult);
  $("token").addEventListener("paste", (e) => {
    e.preventDefault();
    const el = e.target;
    const selected = el.selectionEnd - el.selectionStart;
    const room = Math.max(0, el.maxLength - (el.value.length - selected));
    const text = e.clipboardData
      .getData("text")
      .replace(/\D/g, "")
      .slice(0, room);
    el.setRangeText(text, el.selectionStart, el.selectionEnd, "end");
    el.dispatchEvent(new Event("input"));
  });
  $("window").addEventListener("input", clearResult);
  ["secret", "account", "issuer", "algorithm", "digits", "period"].forEach(
    (id) => $(id).addEventListener("input", update),
  );
  $("verify").addEventListener("submit", verify);
  update();
  tick();
  setInterval(tick, 100);
})();
