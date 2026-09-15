"""
Backfill script: Generate thumbnails for existing bond album photos.

Finds all bond_album_photos documents without a thumb_public_id,
fetches the encrypted full-size image from Cloudinary, decrypts it,
generates a 300x300 JPEG thumbnail, encrypts and uploads it, then
updates the MongoDB document.

Usage:
    cd /path/to/echowithin
    python scripts/backfill_thumbnails.py [--batch-size 20] [--dry-run]
"""
import argparse
import io
import sys
import os

# Add parent directory to path so we can import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_backfill(batch_size=20, dry_run=False):
    """Generate thumbnails for album photos missing thumb_public_id."""
    # Import within function so Flask app context is available
    from main import app, bond_album_photos_conf, cloudinary
    from security import (
        encrypt_media_bytes,
        decrypt_media_bytes,
        generate_signed_cloudinary_url,
    )
    import requests as http_requests

    with app.app_context():
        query = {
            '$or': [
                {'thumb_public_id': {'$exists': False}},
                {'thumb_public_id': ''},
                {'thumb_public_id': None},
            ],
        }
        total = bond_album_photos_conf.count_documents(query)
        print(f"[backfill] Found {total} album photos without thumbnails.")
        if total == 0:
            print("[backfill] Nothing to do.")
            return

        processed = 0
        failed = 0
        skipped = 0
        cursor = bond_album_photos_conf.find(query).batch_size(batch_size)

        for doc in cursor:
            photo_id = doc['_id']
            public_id = doc.get('public_id', '')
            is_media_enc = doc.get('media_encrypted')

            processed += 1
            print(f"[{processed}/{total}] Processing {photo_id} (public_id={public_id[:35] if public_id else 'none'}...)")

            if dry_run:
                print(f"  [DRY RUN] Would generate thumbnail for {photo_id}")
                continue

            try:
                plain = None
                # 1. Fetch image
                if is_media_enc and public_id:
                    signed_url = generate_signed_cloudinary_url(
                        public_id, resource_type='raw', delivery_type='authenticated'
                    )
                    if not signed_url:
                        print(f"  [SKIP] No signed URL for {public_id}")
                        skipped += 1
                        continue

                    resp = http_requests.get(signed_url, timeout=30)
                    if resp.status_code != 200:
                        print(f"  [FAIL] Cloudinary fetch HTTP {resp.status_code}")
                        failed += 1
                        continue

                    plain = decrypt_media_bytes(resp.content)
                elif doc.get('url'):
                    from security import decrypt_bond_data
                    raw_url = doc.get('url', '')
                    if doc.get('encrypted'):
                        try:
                            raw_url = decrypt_bond_data(raw_url, str(doc['bond_id']))
                        except Exception:
                            pass
                    if raw_url and ' ' in raw_url:
                        raw_url = raw_url.replace(' ', '%20')
                    if not raw_url or not raw_url.startswith('http'):
                        print(f"  [SKIP] Invalid url for {photo_id}")
                        skipped += 1
                        continue

                    resp = http_requests.get(raw_url, timeout=30)
                    if resp.status_code != 200:
                        print(f"  [FAIL] Image fetch HTTP {resp.status_code}")
                        failed += 1
                        continue
                    plain = resp.content
                    if is_media_enc:
                        plain = decrypt_media_bytes(plain)

                if not plain:
                    print(f"  [SKIP] No plain image data obtained for {photo_id}")
                    skipped += 1
                    continue

                # 3. Generate 300x300 JPEG thumbnail
                from PIL import Image, ImageOps

                with Image.open(io.BytesIO(plain)) as img:
                    img = ImageOps.exif_transpose(img)
                    img.thumbnail((300, 300), Image.Resampling.LANCZOS)
                    if img.mode in ('RGBA', 'LA'):
                        img = img.convert('RGB')
                    thumb_io = io.BytesIO()
                    img.save(thumb_io, format='JPEG', quality=70, optimize=True)
                    thumb_bytes = thumb_io.getvalue()

                del plain  # Free full image memory

                # 4. Encrypt thumbnail
                thumb_cipher = encrypt_media_bytes(thumb_bytes)
                del thumb_bytes

                # 5. Upload to Cloudinary
                thumb_result = cloudinary.uploader.upload(
                    thumb_cipher,
                    folder='echowithin_bond_album_thumb',
                    resource_type='raw',
                    type='authenticated',
                )
                thumb_pub_id = thumb_result.get('public_id', '')
                del thumb_cipher

                if not thumb_pub_id:
                    print(f"  [FAIL] Cloudinary upload returned no public_id")
                    failed += 1
                    continue

                # 6. Update MongoDB document
                bond_album_photos_conf.update_one(
                    {'_id': photo_id},
                    {'$set': {
                        'thumb_public_id': thumb_pub_id,
                        'thumb_mime_type': 'image/jpeg',
                    }},
                )
                print(f"  [OK] Thumbnail: {thumb_pub_id[:50]}...")

            except Exception as e:
                print(f"  [ERROR] {e}")
                failed += 1

        print(f"\n[backfill] Done. Processed: {processed}, Failed: {failed}, Skipped: {skipped}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Backfill album photo thumbnails')
    parser.add_argument('--batch-size', type=int, default=20, help='Batch size for cursor')
    parser.add_argument('--dry-run', action='store_true', help='Preview without making changes')
    args = parser.parse_args()
    run_backfill(batch_size=args.batch_size, dry_run=args.dry_run)
