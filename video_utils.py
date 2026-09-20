"""
Video compression utility using FFmpeg.

Compresses videos that exceed the Cloudinary raw upload limit before
encryption and upload.  Always outputs H.264/AAC MP4 for maximum
client compatibility.
"""

import logging
import os
import secrets
import subprocess
import tempfile

logger = logging.getLogger(__name__)


def _get_duration(path: str) -> float:
    """Return video duration in seconds using ffprobe."""
    try:
        result = subprocess.run(
            [
                'ffprobe', '-v', 'error',
                '-show_entries', 'format=duration',
                '-of', 'default=noprint_wrappers=1:nokey=1',
                path,
            ],
            capture_output=True, text=True, timeout=30,
        )
        return float(result.stdout.strip())
    except Exception:
        return 0.0


def compress_video_if_needed(
    input_bytes: bytes,
    max_output_bytes: int,
    timeout: int = 120,
    temp_dir: str = 'temp_uploads',
) -> tuple:
    """Compress *input_bytes* so the result fits within *max_output_bytes*.

    Returns ``(output_bytes, mime_type)``.

    * If the input is already small enough it is returned untouched with
      ``mime_type='video/mp4'`` (a safe default since the caller already
      validated the extension).
    * Otherwise FFmpeg re-encodes to H.264+AAC MP4.
    * On any FFmpeg error the **original** bytes are returned so the caller
      can let Cloudinary reject them with a clear size error rather than
      silently swallowing the failure.
    """
    if len(input_bytes) <= max_output_bytes:
        return input_bytes, 'video/mp4'

    os.makedirs(temp_dir, exist_ok=True)
    token = secrets.token_hex(8)
    in_path = os.path.join(temp_dir, f'vc_in_{token}.tmp')
    out_path = os.path.join(temp_dir, f'vc_out_{token}.mp4')

    try:
        # Write source to disk
        with open(in_path, 'wb') as f:
            f.write(input_bytes)

        duration = _get_duration(in_path)
        if duration <= 0:
            logger.warning('Could not determine video duration; skipping compression')
            return input_bytes, 'video/mp4'

        # Target bitrate with 90 % safety margin to stay under the ceiling
        target_total_bits = max_output_bytes * 8 * 0.90
        audio_bitrate = 64_000  # 64 kbps
        video_bitrate = int((target_total_bits / duration) - audio_bitrate)
        if video_bitrate < 50_000:
            # Duration too long for meaningful compression at this ceiling
            logger.warning(
                'Computed video bitrate too low (%d bps for %.1fs); '
                'compression may still exceed limit',
                video_bitrate, duration,
            )
            video_bitrate = 50_000

        compressed = _run_ffmpeg(in_path, out_path, video_bitrate, audio_bitrate, timeout)

        if compressed is not None and len(compressed) <= max_output_bytes:
            logger.info(
                'Video compressed: %d → %d bytes (%.0f%% reduction)',
                len(input_bytes), len(compressed),
                (1 - len(compressed) / len(input_bytes)) * 100,
            )
            return compressed, 'video/mp4'

        # First pass was too large — retry at 70 % bitrate
        if compressed is not None and len(compressed) > max_output_bytes:
            logger.info(
                'First-pass output %d bytes exceeds %d; retrying at 70%% bitrate',
                len(compressed), max_output_bytes,
            )
            retry_bitrate = int(video_bitrate * 0.70)
            if retry_bitrate < 50_000:
                retry_bitrate = 50_000
            # Remove first output before retry
            try:
                os.remove(out_path)
            except OSError:
                pass
            compressed = _run_ffmpeg(in_path, out_path, retry_bitrate, audio_bitrate, timeout)
            if compressed is not None and len(compressed) <= max_output_bytes:
                logger.info(
                    'Retry succeeded: %d → %d bytes', len(input_bytes), len(compressed),
                )
                return compressed, 'video/mp4'

        # Compression did not bring the file under the limit
        logger.warning(
            'Compression could not reduce video below %d bytes; returning original',
            max_output_bytes,
        )
        return input_bytes, 'video/mp4'

    except Exception:
        logger.exception('Video compression failed; returning original bytes')
        return input_bytes, 'video/mp4'
    finally:
        for p in (in_path, out_path):
            try:
                os.remove(p)
            except OSError:
                pass


def _run_ffmpeg(
    in_path: str, out_path: str,
    video_bitrate: int, audio_bitrate: int,
    timeout: int,
) -> bytes | None:
    """Run a single FFmpeg encode pass. Returns output bytes or *None*."""
    cmd = [
        'ffmpeg', '-y', '-i', in_path,
        '-c:v', 'libx264',
        '-preset', 'fast',
        '-b:v', str(video_bitrate),
        '-maxrate', str(video_bitrate),
        '-bufsize', str(video_bitrate * 2),
        '-c:a', 'aac',
        '-b:a', str(audio_bitrate),
        '-movflags', '+faststart',
        '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',
        out_path,
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            logger.error('FFmpeg exited %d: %s', result.returncode, result.stderr[-500:])
            return None
        with open(out_path, 'rb') as f:
            return f.read()
    except subprocess.TimeoutExpired:
        logger.error('FFmpeg timed out after %d seconds', timeout)
        return None
    except Exception:
        logger.exception('FFmpeg execution error')
        return None
