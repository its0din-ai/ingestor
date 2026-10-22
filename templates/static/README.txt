Vendored front-end assets

- Roboto (Apache License 2.0) - Google Fonts, latin subset, variable weight.
- Red Hat Mono (SIL Open Font License 1.1) - Google Fonts, latin subset, variable weight.
- anime.js 3.2.2 (MIT) - https://animejs.com

These files are served from /static/ so the application remains fully
self-contained in airgapped deployments. Google Sans is proprietary and is
therefore requested first from locally installed fonts, with Roboto as the
bundled fallback.
