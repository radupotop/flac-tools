## FLAC tools

Various tools to verify the integrity of FLAC files.

Can verify EAC-compatible log files / [Whipper] log files made with whipper-plugin-eaclogger.

## Usage

    flac-crc32 *.flac
    flac-md5 *.flac
    whipper-verify-crc.py eac-logfile.log

With [fd] you can run `flac-crc32` or `flac-md5` in parallel over the entire fileset:

    fd -e flac -x flac-md5

Note that this is non-deterministic; the output order will vary with each run.

[fd]: https://github.com/sharkdp/fd
[Whipper]: https://github.com/whipper-team/whipper
