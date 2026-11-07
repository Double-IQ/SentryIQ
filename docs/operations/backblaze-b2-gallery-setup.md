# Configure Backblaze B2 for SentryIQ Gallery

This configuration is for the zero-knowledge Gallery storage implementation on the
\`feature/zero-knowledge-gallery-storage\` branch. Do not enable it for production until the Gallery browser flow and its security tests have passed.

## 1. Create a private bucket

1. Enable Backblaze B2 Cloud Storage.
2. Create a dedicated bucket for SentryIQ Gallery.
3. Keep the bucket **private**. Do not enable public file access or public bucket listing.
4. Record the bucket name and its region. The S3 endpoint has the form
   \`https://s3.<region>.backblazeb2.com\`.

## 2. Create a restricted application key

Create an application key for this bucket only. Grant only the object operations needed by Gallery:

- Read files (for signed downloads and object checks).
- Write files (for direct browser uploads).
- Delete files (for Gallery deletion).

Do not use the Backblaze account master application key. Do not grant bucket administration or bucket-listing permissions unless a later, documented operation requires them.

The S3-compatible API uses AWS Signature Version 4. SentryIQ creates short-lived signed URLs on the server; the key ID and application key are never returned to the browser.

## 3. Connect from SentryIQ

1. Sign in and unlock the SentryIQ vault.
2. Open **Gallery → Backblaze Storage Settings**.
3. Enter the bucket name, B2 region, bucket-scoped application key ID, and application key.
4. Save. SentryIQ validates the fields and writes `gallery_b2.php` automatically inside the protected `data_dir`, outside the public web root, with owner-only (`0600`) permissions.
5. Run the built-in connection test before uploading photos.

The credentials are stored only in the protected server-side runtime file. They are not written to the repository, database, browser storage, or returned to the page. Saving or disconnecting requires a fresh vault unlock.

For manual recovery or deployments where the settings page is unavailable, `docs/examples/gallery_b2.php.example` remains a reference template. Never commit real credentials.

## 4. Configure bucket CORS

Configure the bucket CORS policy for the exact SentryIQ application origin (scheme, hostname and non-default port only; no path).

Allow only the methods needed by the browser flow:

- \`PUT\` for ciphertext uploads.
- \`GET\` for ciphertext downloads.
- \`DELETE\` for object deletion.
- \`HEAD\` only if enabled for object verification.

Allow the \`Content-Type\` request header. Expose only response headers the client actually needs (initially, none are required for the Gallery cryptographic flow). Do not use wildcard origins.

## Image handling and metadata

The browser decodes selected images and re-encodes the stored original, preview and thumbnail as WebP before encryption. This strips source EXIF metadata such as embedded GPS coordinates. The original source-file bytes are not retained or uploaded. Filenames, album labels and dimensions are included only inside the encrypted metadata object.

## 6. Verify before enabling uploads

- Confirm the bucket is private from an unauthenticated browser.
- Confirm the PHP runtime can read the protected config file.
- Confirm the configured key is restricted to the intended bucket.
- Confirm signed \`PUT\`, \`GET\`, and \`DELETE\` requests work against the configured regional endpoint.
- Confirm CORS permits requests from the exact SentryIQ origin and rejects other origins.
- Confirm uploaded object bytes are ciphertext, not a directly viewable image.
- Confirm expired signed URLs stop working.

B2 versioning means deleting an object by name may create a delete marker while older versions remain in the bucket. Configure lifecycle cleanup or an explicit version-deletion policy if permanent removal of historical versions is required.
