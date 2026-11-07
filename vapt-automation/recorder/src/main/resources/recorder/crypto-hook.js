// VAPT recorder - passive in-page hook (read-only observer).
// Wraps WebCrypto AES-GCM encrypt/decrypt so the recorder can see the plain text of an app's
// encrypted request/response bodies. It never changes what the app sends or receives: the
// original function runs first and its result is returned unchanged.
// Each event carries base64(iv || ciphertext||tag), which is exactly the "payload" /
// "responseObject" string on the wire, so the recorder can match plain text to the right call.
(() => {
  if (window.__vaptHooked) return;
  window.__vaptHooked = true;

  // ---- module label overlay (tester types the module they are walking) ----
  const addOverlay = () => {
    if (!window.__vaptOverlay || document.getElementById('__vapt_module_box')) return;
    const box = document.createElement('div');
    box.id = '__vapt_module_box';
    box.style.cssText = 'position:fixed;right:8px;bottom:8px;z-index:2147483647;background:#0f2a4a;color:#fff;'
      + 'font:12px Segoe UI,Arial;padding:6px 8px;border-radius:6px;opacity:.9;box-shadow:0 1px 4px #0006';
    box.innerHTML = 'VAPT module: <input id="__vapt_module_input" style="width:130px;font:12px Segoe UI" placeholder="e.g. Master">';
    document.documentElement.appendChild(box);
    const input = box.querySelector('input');
    input.value = sessionStorage.getItem('__vapt_module') || '';
    input.addEventListener('change', () => {
      sessionStorage.setItem('__vapt_module', input.value);
      try { window.__vaptModule && window.__vaptModule(input.value); } catch (e) {}
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', addOverlay);
  else addOverlay();

  // ---- WebCrypto observer ----
  const subtle = window.crypto && window.crypto.subtle;
  if (!subtle) return;
  const toU8 = (d) => {
    if (d instanceof ArrayBuffer) return new Uint8Array(d);
    if (ArrayBuffer.isView(d)) return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
    return new Uint8Array(0);
  };
  const b64 = (u8) => {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const isGcm = (algo) => !!algo && String(algo.name || algo).toUpperCase() === 'AES-GCM' && !!algo.iv;
  const pack = (iv, ct) => { const p = new Uint8Array(iv.length + ct.length); p.set(iv); p.set(ct, iv.length); return p; };
  const text = new TextDecoder();
  const report = (kind, blob, plain) => {
    try { window.__vaptCrypto && window.__vaptCrypto(JSON.stringify({ kind, blob, plain })); } catch (e) {}
  };

  const origEncrypt = subtle.encrypt.bind(subtle);
  const origDecrypt = subtle.decrypt.bind(subtle);

  subtle.encrypt = async function (algo, key, data) {
    const out = await origEncrypt(algo, key, data);
    try {
      if (isGcm(algo)) report('enc', b64(pack(toU8(algo.iv), new Uint8Array(out))), text.decode(toU8(data)));
    } catch (e) {}
    return out;
  };

  subtle.decrypt = async function (algo, key, data) {
    const out = await origDecrypt(algo, key, data);
    try {
      if (isGcm(algo)) report('dec', b64(pack(toU8(algo.iv), toU8(data))), text.decode(new Uint8Array(out)));
    } catch (e) {}
    return out;
  };
})();
