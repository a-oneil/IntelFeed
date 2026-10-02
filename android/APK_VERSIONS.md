# IntelFeed APK versions

Every APK copied to `../IntelFeed.apk` gets a new version and a row here, newest first. The app shows its version at the bottom of **Settings** ("IntelFeed for Android 1.1 (build 2)"), so you can check which one a phone has.

**How to release (Claude and Gemini):** run `tools/release_apk.sh "<what changed>" [--by Claude|Gemini] [--major]` from the project root. It bumps `version.properties` (build number +1, version 1.x → 1.x+1, or 2.0 with `--major`), runs the unit tests and builds, copies the APK to `../IntelFeed.apk`, adds a row below, and installs it on every connected device (emulator and phone) with data kept. Don't edit the version in `app/build.gradle.kts`; it reads `version.properties`. Details of each change stay in `claude_changes.md`.

**Publishing on GitHub:** commit, then run `tools/sync_to_github.sh "<what changed>"`. It opens a pull request to `android/` in a-oneil/IntelFeed. Once it's merged, CI publishes the new version as the release `android-v<version>`, with `IntelFeed.apk` attached (see `README.md`). A version that already has a release isn't published again, so release a new version first.

| Version | Build | Date | SHA-256 (first 12) | By | What changed | Installed on |
|---|---|---|---|---|---|---|
| 1.2 | 3 | 2026-09-24 15:43 | 75001a8e9145 | Claude | Day chips follow the open view's time range (24h / 7 days) and the filter bar has a range picker (that day, 24h, 7, 30 days, all time) | emulator, Pixel 9 Pro |
| 1.1 | 2 | 2026-09-24 15:19 | a53cdd8d356a | Claude | Version tracking starts: version shown in Settings; same features as 1.0's last build | emulator, Pixel 9 Pro |
| 1.0 | 1 | 2026-09-22 → 2026-09-24 15:10 | 7212b93c8f6f (last) | Claude, Gemini, Codex | Every APK before version tracking; the last one has the ATT&CK Matrix, Ransomware tracker, relationship graph, web-matching highlighting and tags | Pixel 9 Pro, emulator |
