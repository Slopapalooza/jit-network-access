# Chrome Web Store assets

Everything here is generated. Do not hand-edit the PNGs — change the sources in
`docs/img/` (or the captions in `make-assets.py`) and re-run:

```bash
python3 extension/store-assets/make-assets.py
```

Needs Pillow (`python3 -m pip install Pillow`). Sources are never modified.

## Screenshots

The store accepts **1280×800 or 640×400 and nothing else**, and allows **at most
five**. The sources are whatever size the window happened to be, so each is
letterboxed onto a 1280×800 canvas with a caption rather than stretched.

Upload these four, in this order — they are the whole budget if you also want a
fifth:

| File | Shows |
|---|---|
| `01-locked.png` | Popup on a protected site that has not been knocked yet |
| `02-unlocked.png` | Same site after the knock |
| `03-enroll.png` | The enrollment confirm page, naming the origins being granted |
| `04-options.png` | Options page — enrolled devices, no secrets shown |

## Not for the listing (probably)

`optional-05-admin-overview.png`, `optional-06-admin-create.png` and
`optional-07-admin-link.png` are the **server-side** BunkerWeb plugin UI. They
explain the system well, but Chrome asks that screenshots demonstrate the
extension itself, and an admin console is not the extension. Including one risks
a "screenshots do not depict the product" rejection. They are built here so the
choice is yours; the default assumption is that they are not uploaded.

## Redaction

Every screenshot uses `app.example.com` / `intranet.example.com`, fabricated key
ids (`kid_7Kd93nR2mv`, `kid_QpZ4TfL8wc`) and `DEMO-ONE-TIME-CODE`. This
repository is public and a store listing is more public still — **check any
replacement screenshot for real hostnames, addresses or key ids before it goes
in here.**

## Still missing before the listing can be submitted

- **Extension icon.** `manifest.json` has `"icons": {}`. The store needs a
  128×128 in the manifest and a 128×128 store icon. Nothing here supplies one.
- **Small promo tile**, 440×280, if you want the listing to be eligible for
  promotion. Optional.

## Related

- Listing copy and permission justifications: kept with the release notes, not
  in the repo.
- Privacy policy (required field, this extension handles key material):
  [`docs/PRIVACY.md`](../../docs/PRIVACY.md)
