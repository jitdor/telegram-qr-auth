// Server-side QR rendering. The whole point of doing this here rather than in the browser: the
// deep link embeds a live one-time login token, and it should never travel to a third-party
// image-generation service (api.qrserver.com, chart.googleapis.com and friends) or sit in a
// client-side JS variable before it is displayed. It goes straight from the token store into an
// inline <svg> in the response body.

import qrcode from "./qrcode-generator.js";

const MAX_TYPE_NUMBER = 40; // QR versions run 1..40; 40 holds far more than any t.me deep link

/**
 * Renders `text` as a self-contained SVG QR code, picking the smallest QR version that fits.
 *
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.cellSize=6]        Pixel size of one QR module.
 * @param {number} [options.margin=4]          Quiet zone in modules. 4 is the spec minimum; going
 *                                             lower makes scanners fail against busy backgrounds.
 * @param {string} [options.dark="#0f172a"]    Foreground colour.
 * @param {string} [options.light="#ffffff"]   Background colour. Must stay opaque and light —
 *                                             a transparent QR on a dark page does not scan.
 * @param {string} [options.errorCorrection="M"]  "L" | "M" | "Q" | "H".
 * @param {string} [options.label]             aria-label for screen readers.
 * @returns {string} SVG markup
 */
export function qrSvg(text, options = {}) {
  const {
    cellSize = 6,
    margin = 4,
    dark = "#0f172a",
    light = "#ffffff",
    errorCorrection = "M",
    label = "QR code — scan with Telegram to sign in",
  } = options;

  let qr = null;
  for (let typeNumber = 1; typeNumber <= MAX_TYPE_NUMBER; typeNumber++) {
    try {
      const candidate = qrcode(typeNumber, errorCorrection);
      candidate.addData(text);
      candidate.make();
      qr = candidate;
      break;
    } catch {
      // Data doesn't fit this version — try the next one up.
    }
  }
  if (!qr) throw new Error("QR data too long to encode");

  const count = qr.getModuleCount();
  const size = (count + margin * 2) * cellSize;

  // One <path> of same-size squares rather than thousands of <rect> elements: roughly a third of
  // the bytes, and it survives being inlined into an HTML page without a layout cost.
  let path = "";
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) {
        const x = (col + margin) * cellSize;
        const y = (row + margin) * cellSize;
        path += `M${x} ${y}h${cellSize}v${cellSize}h-${cellSize}z`;
      }
    }
  }

  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" ` +
    `shape-rendering="crispEdges" role="img" aria-label="${escapeXmlAttr(label)}">` +
    `<rect width="${size}" height="${size}" fill="${escapeXmlAttr(light)}"/>` +
    `<path d="${path}" fill="${escapeXmlAttr(dark)}"/></svg>`
  );
}

function escapeXmlAttr(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** The SVG above as a `data:` URI, for the rare consumer that needs an <img src> instead of inline markup. */
export function qrDataUri(text, options) {
  // Encode via TextEncoder rather than the legacy `unescape(encodeURIComponent(...))` trick, which
  // is not guaranteed to exist outside browsers.
  const bytes = new TextEncoder().encode(qrSvg(text, options));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return `data:image/svg+xml;base64,${btoa(bin)}`;
}
