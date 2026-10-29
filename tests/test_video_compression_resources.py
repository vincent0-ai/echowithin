"""Resource-guard tests for video compression.

These lock in the cheap encoding defaults. The output is always bitrate-capped,
so a slower x264 preset spends more CPU without producing a smaller file.
"""
import video_utils


class TestEncoderPreset:
    def test_preset_is_cheap_one(self):
        """'fast' cost ~1.7x the CPU of 'veryfast' for a byte-identical result."""
        assert video_utils.FFMPEG_PRESET in {'ultrafast', 'superfast', 'veryfast'}

    def test_preset_is_not_the_expensive_default(self):
        assert video_utils.FFMPEG_PRESET != 'fast'

    def test_preset_is_a_valid_x264_value(self):
        assert video_utils.FFMPEG_PRESET in {
            'ultrafast', 'superfast', 'veryfast', 'faster', 'fast',
            'medium', 'slow', 'slower', 'veryslow',
        }


class TestFfmpegCommand:
    def test_no_threads_flag(self):
        """'-threads 1' broke libx264 on the deployed build; must not return."""
        import inspect
        src = inspect.getsource(video_utils._run_ffmpeg)
        assert "'-threads'" not in src

    def test_uses_bitrate_cap(self):
        import inspect
        src = inspect.getsource(video_utils._run_ffmpeg)
        assert '-maxrate' in src and '-b:v' in src

    def test_faststart_enabled(self):
        """moov up front keeps in-vault playback streamable."""
        import inspect
        src = inspect.getsource(video_utils._run_ffmpeg)
        assert '+faststart' in src


class TestBuffersReleased:
    def test_retry_drops_previous_output(self):
        """A failed pass must be freed before the retry encodes again."""
        import inspect
        src = inspect.getsource(video_utils.compress_video_if_needed)
        assert 'compressed = None' in src
