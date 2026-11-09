const picker = document.getElementById("apk");
const result = document.getElementById("result");
const status = document.getElementById("status");
const nameField = document.getElementById("name");
const sizeField = document.getElementById("size");
const formatField = document.getElementById("format");
const structureField = document.getElementById("structure");
const hashField = document.getElementById("hash");
const clearButton = document.getElementById("clear");

function formatBytes(bytes) {
  if (!bytes) return "0 bytes";
  const units = ["bytes", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 2) + " " + units[index];
}

// Reads ZIP directory metadata only; the APK is never uploaded or extracted.
async function inspectApkZip(file) {
  const tailLength = Math.min(file.size, 22 + 65535);
  const tail = await file.slice(file.size - tailLength).arrayBuffer();
  const view = new DataView(tail);
  let eocd = -1;

  for (let i = view.byteLength - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      if (i + 22 + view.getUint16(i + 20, true) === view.byteLength) {
        eocd = i;
        break;
      }
    }
  }
  if (eocd < 0) throw new Error("ZIP directory record not found");

  const entries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (entries === 0xffff || centralOffset === 0xffffffff || centralSize === 0xffffffff) {
    throw new Error("This ZIP64 APK is not supported yet");
  }
  if (centralOffset + centralSize > file.size) throw new Error("ZIP directory points outside the file");

  const centralBuffer = await file.slice(centralOffset, centralOffset + centralSize).arrayBuffer();
  const central = new DataView(centralBuffer);
  const decoder = new TextDecoder();
  let hasManifest = false;
  let hasDex = false;
  let hasResources = false;
  let offset = 0;

  for (let i = 0; i < entries; i++) {
    if (offset + 46 > central.byteLength || central.getUint32(offset, true) !== 0x02014b50) {
      throw new Error("Invalid ZIP directory entry");
    }
    const nameLength = central.getUint16(offset + 28, true);
    const extraLength = central.getUint16(offset + 30, true);
    const commentLength = central.getUint16(offset + 32, true);
    const next = offset + 46 + nameLength + extraLength + commentLength;
    if (next > central.byteLength) throw new Error("Truncated ZIP directory entry");

    const name = decoder.decode(new Uint8Array(centralBuffer, offset + 46, nameLength));
    if (name === "AndroidManifest.xml") hasManifest = true;
    if (/^classes(?:[0-9]+)?\\.dex$/.test(name)) hasDex = true;
    if (name === "resources.arsc") hasResources = true;
    offset = next;
  }
  return { entries, hasManifest, hasDex, hasResources };
}

picker.addEventListener("change", async () => {
  const file = picker.files && picker.files[0];
  if (!file) return;

  result.classList.add("show");
  nameField.textContent = file.name;
  sizeField.textContent = formatBytes(file.size);
  formatField.textContent = "Checking…";
  structureField.textContent = "Checking APK contents…";
  hashField.textContent = "Calculating…";
  status.textContent = "Inspecting file locally…";
  status.className = "status";

  // Run hashing independently so a ZIP parsing problem cannot leave it pending.
  const hashTask = (async () => {
    try {
      if (!crypto.subtle) throw new Error("Secure context required");
      const bytes = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      hashField.textContent = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
    } catch {
      hashField.textContent = "Not available in this browser context";
    }
  })();

  try {
    const looksLikeApk = file.name.toLowerCase().endsWith(".apk");
    const header = new Uint8Array(await file.slice(0, 4).arrayBuffer());
    const isZip = header.length === 4 && header[0] === 0x50 && header[1] === 0x4b &&
      ((header[2] === 0x03 && header[3] === 0x04) ||
       (header[2] === 0x05 && header[3] === 0x06) ||
       (header[2] === 0x07 && header[3] === 0x08));

    if (!looksLikeApk || !isZip) {
      formatField.textContent = looksLikeApk ? "APK extension found, ZIP signature missing" : "File does not end in .apk";
      structureField.textContent = "Not checked";
      status.textContent = "This file may not be a valid APK";
      status.className = "status bad";
      return;
    }

    const info = await inspectApkZip(file);
    const checks = [
      info.hasManifest ? "Manifest ✓" : "Manifest missing ✕",
      info.hasDex ? "DEX ✓" : "DEX missing ✕",
      info.hasResources ? "Resources ✓" : "Resources absent"
    ];
    formatField.textContent = "ZIP directory readable";
    structureField.textContent = checks.join(" · ") + " · " + info.entries + " ZIP entries";
    const complete = info.hasManifest && info.hasDex;
    status.textContent = complete ? "Basic APK structure checks passed" : "APK structure looks incomplete";
    status.className = complete ? "status ok" : "status bad";
  } catch (error) {
    formatField.textContent = "Check failed";
    structureField.textContent = error && error.message ? error.message : "Could not read this file";
    status.textContent = "Could not inspect APK structure";
    status.className = "status bad";
  } finally {
    await hashTask;
  }
});

clearButton.addEventListener("click", () => {
  picker.value = "";
  result.classList.remove("show");
});
if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  window.addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(() => {}));
}
