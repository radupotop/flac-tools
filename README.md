## FLAC tools

Various tools to verify the integrity of FLAC files.

## Usage

    flac-crc32 *.flac
    flac-md5 *.flac
    whipper-verify-crc.py eac-logfile.log

With [fd] you can run `flac-crc32` or `flac-md5` in parallel over the entire fileset:

    fd -e flac -x flac-md5

[fd]: https://github.com/sharkdp/fd
