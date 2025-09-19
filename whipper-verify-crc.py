#!/usr/bin/env python3
# Verify Whipper/EAC logs having CRC32 per-track checksums

import argparse
import re
import subprocess
import sys
import wave
import zlib
from pathlib import Path
from typing import Dict, Optional, Tuple

# Regexes for parsing EAC/Whipper logs
LOG_CRC_RE = (
    re.compile(r"^\s*Copy CRC\s+([0-9A-Fa-f]{8})\s*$"),  # EAC/Whipper
    re.compile(r"^\s*CRC32 hash\s+\:\s([0-9A-Fa-f]{8})\s*$"),  # XLD Mac
)
TRACK_HEADER_RE = re.compile(r"^\s*Track\s+(\d+)\s*$")
NULLS_RE = re.compile(
    r"^\s*Null samples used in CRC calculations\s*:\s*(Yes|No)\s*$", re.I
)


def read_text_auto(path: Path) -> Tuple[str, str]:
    """Read text with simple BOM-based auto-detection (UTF-8/UTF-16LE/UTF-16BE), fallback to cp1252."""
    raw = path.read_bytes()
    enc: Optional[str] = None
    if raw.startswith(b"\xef\xbb\xbf"):
        enc = "utf-8-sig"
    elif raw.startswith(b"\xff\xfe"):
        enc = "utf-16-le"
    elif raw.startswith(b"\xfe\xff"):
        enc = "utf-16-be"
    else:
        # Heuristic for UTF-16 without BOM: lots of NUL bytes in first chunk
        if b"\x00" in raw[:200]:
            for e in ("utf-16-le", "utf-16-be"):
                try:
                    return raw.decode(e), e
                except Exception:
                    pass
        enc = "utf-8"
    try:
        return raw.decode(enc), enc  # type: ignore[arg-type]
    except Exception:
        return raw.decode("cp1252", errors="replace"), "cp1252"


def parse_log(path: Path) -> Tuple[bool, Dict[int, str], str]:
    """Parse the log to extract (use_nulls, {track_num: CRC}, detected_encoding)."""
    text, enc = read_text_auto(path)
    use_nulls = True  # default like EAC/Whipper
    expected: Dict[int, str] = {}
    current_track: Optional[int] = None
    for line in text.splitlines():
        m = NULLS_RE.match(line)
        if m:
            use_nulls = m.group(1).strip().lower() == "yes"
            continue
        m = TRACK_HEADER_RE.match(line)
        if m:
            current_track = int(m.group(1))
            continue
        for crc_re in LOG_CRC_RE:
            m = crc_re.match(line)
            if m and current_track is not None:
                expected[current_track] = m.group(1).upper()
                break
    return use_nulls, expected, enc


def find_track_file(basedir: Path, track_num: int) -> Optional[Path]:
    """Locate a track file by common naming patterns like '01. Title.flac' or '01 - Title.wav'."""
    prefixes = (f"{track_num:02d}.", f"{track_num:02d} -", f"{track_num:02d} ")
    exts = (".flac", ".wav")
    candidates = []
    try:
        for p in basedir.iterdir():
            if not p.is_file():
                continue
            name = p.name
            if (
                any(name.startswith(pref) for pref in prefixes)
                and p.suffix.lower() in exts
            ):
                candidates.append(p)
    except FileNotFoundError:
        return None
    if not candidates:
        return None
    # Prefer FLAC over WAV, then sort by name for determinism
    candidates.sort(
        key=lambda p: (0 if p.suffix.lower() == ".flac" else 1, p.name.lower())
    )
    return candidates[0]


def _run(cmd):
    """Run a command, return (rc, stdout_bytes, stderr_text)."""
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
    except FileNotFoundError as e:
        return 127, b"", f"{e}"
    stderr = res.stderr.decode("utf-8", errors="replace")
    return res.returncode, res.stdout, stderr


def decode_to_pcm_bytes(path: Path) -> bytes:
    """Decode FLAC/WAV to raw PCM bytes using flac --totally-silent for FLAC; ignore exit code if bytes exist."""
    suf = path.suffix.lower()
    if suf == ".flac":
        rc, out, err = _run(
            [
                "flac",
                "--decode",
                "--stdout",
                "--totally-silent",
                "--force-raw-format",
                "--endian=little",
                "--sign=signed",
                str(path),
            ]
        )
        if out:  # accept bytes even if rc != 0
            return out
        raise RuntimeError(
            f"flac produced no PCM on stdout (rc={rc}). Stderr: {err.strip() or 'no stderr'}"
        )
    elif suf == ".wav":
        # Read WAV frames (header skipped), yields raw PCM bytes
        with wave.open(str(path), "rb") as w:
            return w.readframes(w.getnframes())
    else:
        raise ValueError(f"Unsupported file type: {path}")


def trim_null_frames(pcm: bytes, sample_width: int = 2, channels: int = 2) -> bytes:
    """Trim leading/trailing all-zero frames for the 'W/O NULL' variant."""
    frame_size = sample_width * channels
    if frame_size <= 0 or len(pcm) % frame_size != 0:
        return pcm
    mv = memoryview(pcm)
    total_frames = len(pcm) // frame_size
    start = 0
    while start < total_frames and not any(
        mv[start * frame_size : (start + 1) * frame_size]
    ):
        start += 1
    end = total_frames
    while end > start and not any(mv[(end - 1) * frame_size : end * frame_size]):
        end -= 1
    return pcm[start * frame_size : end * frame_size]


def crc32_hex(data: bytes) -> str:
    return f"{(zlib.crc32(data) & 0xFFFFFFFF):08X}"


def main():
    ap = argparse.ArgumentParser(
        description="Verify Whipper/EAC-style per-track CRC32 against a log file."
    )
    ap.add_argument("logfile", help="Path to Whipper/EAC log (.log)")
    ap.add_argument(
        "-d",
        "--audio-dir",
        default=None,
        help="Directory with audio files (defaults to log's directory)",
    )
    ap.add_argument(
        "-N",
        "--wo-null",
        action="store_true",
        help="Force 'without null samples' CRC (override log)",
    )
    args = ap.parse_args()

    print(f"Processing log file: {args.logfile}")
    log_path = Path(args.logfile).expanduser().resolve()

    use_nulls, expected, enc = parse_log(log_path)
    if not expected:
        sys.exit("No CRC32 entries found in log. Is this a EAC-style log?")

    if args.wo_null:
        use_nulls = False

    basedir = (
        Path(args.audio_dir).expanduser().resolve() if args.audio_dir else log_path.parent
    )

    print(f"Parsed log with encoding: {enc}")
    print(f"Null samples used per log: {'Yes' if use_nulls else 'No'}")
    ok = fail = missing = 0

    for track in sorted(expected.keys()):
        audio_path = find_track_file(basedir, track)
        if audio_path is None:
            print(f"Track {track:02d}: MISSING audio file")
            missing += 1
            continue
        try:
            pcm = decode_to_pcm_bytes(audio_path)
        except Exception as e:
            print(f"Track {track:02d}: ERROR decoding {audio_path.name}: {e}")
            fail += 1
            continue

        if not use_nulls:
            pcm = trim_null_frames(pcm)

        got = crc32_hex(pcm)
        exp = expected[track]
        status = "OK" if got == exp else "FAIL"
        if status == "OK":
            ok += 1
        else:
            fail += 1
        print(
            f"Track {track:02d}: {audio_path.name}  expected={exp}  got={got}  [{status}]"
        )

    total = len(expected)
    print(f"\nSummary: {ok}/{total} OK, {fail} FAIL, {missing} missing\n")
    sys.exit(bool(fail) or bool(missing))


if __name__ == "__main__":
    main()
