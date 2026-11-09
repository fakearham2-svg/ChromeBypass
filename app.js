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

// Reads ZIP directory metadata only; it does not extract or upload the APK.
async function inspectApkZip(file) {
  const tailLength = Math.min(file.size, 22 + 65535);
  const tailStart = file.size - tailLength;
  const tail = await file.slice(tailStart).arrayBuffer();
  const view = new DataView(tail);
  let eocd = -1;

  for (let i = tail.byteLength - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      const commentLength = view.getUint16(i + 20, true);
      if (i + 22 + commentLength === tail.byteLength) { eocd = i; break; }
    }
  }
  if (eocd < 0) throw new Error("ZIP directory record not found");

  const entries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (entries === 0xffff || centralOffset === 0xffffffff || centralSize === 0xffffffff) {
    throw new Error("ZIP64 APK is not supported by this basic inspector");
  }
  if (centralOffset + centralSize > file.size) throw new Error("ZIP directory points outside the file");

  const central = new DataView(await file.slice(centralOffset, centralOffset + centralSize).arrayBuffer());
  const decoder = new TextDecoder();
  const names = [];
  let offset = 0;
  for (let i = 0; i < entries; i++) {
    if (offset + 46 > central.byteLength || central.getUint32(offset, true) !== 0x02014b50) {
      throw new Error("Invalid ZIP directory entry");
    }
    const nameLength = central.getUint16(offset + 28, true);
    const extraLength = central.getUint16(offset + 30, true);
    const commentLength = central.getUint16(offset + 32, true);
    if (offset + 46 + nameLength + extraLength + commentLength > central.byteLength) {
      throw new Error("Truncated ZIP directory entry");
    }
    const nameBytes = new Uint8Array(central.buffer, central.byteOffset + offset + 46, nameLength);
    names.push(decoder.decode(nameBytes));
    offset += 46 + nameLength + extraLength + commentLength;
  }

  const hasManifest = names.includes("AndroidManifest.xml");
  const hasDex = names.some(name => /^classes(?:[0-9]+)?\.dex$/.test(name));
  const hasResources = names.includes("resources.arsc");
  return { entries, hasManifest, hasDex, hasResources };
}

picker.addEventListener("change", async () => {
  const file = picker.files && picker.files[0];
  if (!file) return;
  result.classList.add("show");
  nameField.textContent = file.name;
  sizeField.textContent = formatBytes(file.size);
  hashField.textContent = "Calculating…";
  structureField.textContent = "Checking APK contents…";

  const looksLikeApk = file.name.toLowerCase().endsWith(".apk");
  const header = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  const isZip = header.length === 4 && header[0] === 0x50 && header[1] === 0x4b &&
    ((header[2] === 0x03 && header[3] === 0x04) ||
     (header[2] === 0x05 && header[3] === 0x06) ||
     (header[2] === 0x07 && header[3] === 0x08));

  if (looksLikeApk && isZip) {
    try {
      const info = await inspectApkZip(file);
      const checks = [
        info.hasManifest ? "Manifest ✓" : "Manifest missing ✕",
        info.hasDex ? "DEX ✓" : "DEX missing ✕",
        info.hasResources ? "Resources ✓" : "Resources absent"
      ];
      structureField.textContent = checks.join(" · ") + " · " + info.entries + " ZIP entries";
      const looksComplete = info.hasManifest && info.hasDex;
      status.textContent = looksComplete ? "APK structure checks passed (basic)" : "APK structure looks incomplete";
      status.className = looksComplete ? "status ok" : "status bad";
      formatField.textContent = "ZIP directory readable";
    } catch (error) {
      structureField.textContent = error.message;
      status.textContent = "Could not inspect APK structure";
      status.className = "status bad";
      formatField.textContent = "ZIP/APK structure check failed";
    }
  } else {
    status.textContent = "This file may not be a valid APK";
    status.className = "status bad";
    formatField.textContent = looksLikeApk ? "APK extension found, ZIP signature missing" : "File does not end in .apk";
    structureField.textContent = "Not checked";
  }

  try {
    if (!crypto.subtle) throw new Error("Secure context required");
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    hashField.textContent = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
  } catch {
    hashField.textContent = "Not available in this browser context";
  }
});

clearButton.addEventListener("click", () => {
  picker.value = "";
  result.classList.remove("show");
});
if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  window.addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(() => {}));
}
