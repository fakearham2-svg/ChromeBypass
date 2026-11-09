const picker = document.getElementById("apk");
const result = document.getElementById("result");
const status = document.getElementById("status");
const nameField = document.getElementById("name");
const sizeField = document.getElementById("size");
const formatField = document.getElementById("format");
const hashField = document.getElementById("hash");
const clearButton = document.getElementById("clear");

function formatBytes(bytes) {
  if (!bytes) return "0 bytes";
  const units = ["bytes", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 2) + " " + units[index];
}

picker.addEventListener("change", async () => {
  const file = picker.files && picker.files[0];
  if (!file) return;
  result.classList.add("show");
  nameField.textContent = file.name;
  sizeField.textContent = formatBytes(file.size);
  hashField.textContent = "Calculating…";

  const looksLikeApk = file.name.toLowerCase().endsWith(".apk");
  const header = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  const isZip = header.length === 4 && header[0] === 0x50 && header[1] === 0x4b &&
    ((header[2] === 0x03 && header[3] === 0x04) ||
     (header[2] === 0x05 && header[3] === 0x06) ||
     (header[2] === 0x07 && header[3] === 0x08));

  if (looksLikeApk && isZip) {
    status.textContent = "File selected — ZIP container signature found";
    status.className = "status ok";
    formatField.textContent = "Looks like an APK container (basic check only)";
  } else {
    status.textContent = "This file may not be a valid APK";
    status.className = "status bad";
    formatField.textContent = looksLikeApk ? "APK extension found, ZIP signature missing" : "File does not end in .apk";
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