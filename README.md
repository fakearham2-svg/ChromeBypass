# ChromeBypass

A Chromebook-friendly, browser-based APK file checker.

## What it does
- Lets you choose an APK file from the device.
- Shows the filename and file size.
- Performs a basic ZIP-container signature check.
- Calculates a SHA-256 checksum locally in the browser.

## Important limitation
This project does **not** install APKs and does not bypass ChromeOS security restrictions. APK installation must use an installation method supported and permitted by ChromeOS on the device.

## Deploy to GitHub Pages
1. Open **Settings → Pages** in this repository.
2. Under **Build and deployment**, choose **GitHub Actions** as the source.
3. Open the **Actions** tab and run **Deploy ChromeBypass web app**, or push a new commit to `main`.
4. When the workflow completes, open the Pages URL shown in the deployment.

The file is processed locally by your browser; this page does not upload it.