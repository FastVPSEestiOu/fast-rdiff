### Brief 

This is very fast (thanks to C++) impelementation of rdiff algorithm (delta difference, librsync, rdiff). Actually, rdiff should not be used in production due to significant performance issues: https://github.com/librsync/librsync/issues/6

We support only delta generation and ONLY for 1MB block files (we are using fast-rdiff for OpenVZ ploop files).

We haven't support for "rdiff path" but original rdiff could be used for this purpose. But please be careful! fast-rdiff is using md4 algorithm and you could explicitly specify it to new rdiff:= with option: --hash=md4

### Examples

```
FASTRDIFF_META_FILE_NAME=/tmp/metafile ./fastrdiff signature_for_old_file_version new_file_version delta_path
```

Delta path could be "-" (i.e. stdout) and all delta information will be printed on stdout.

So we also will dump very useful information to /tmp/metafile (source_data_size, source_data_md5, delta_data_md5, delta_data_size). This information should be stored together with genetrated dump file for data validation on restore.

### IMPORTANT

We support only delta generation and ONLY for 1MB block files. All other file sizes is UNSUPPORTED!

### Build

```bash
# CentOS / RHEL
yum install -y openssl-devel cmake gcc make log4cpp-devel


cd /usr/src
git clone https://github.com/FastVPSEestiOu/fast-rdiff.git
cd fast-rdiff
mkdir build
cd build
cmake ..
make
```

### Is it mature?

Yes, it's very well tested. We are using it to generate and restore about 500TB of customer backups. We are using this code for last 2 year without any issues. Thanks to bundled checksumm support for all steps (for delta, for original file) we could be sure in data integrity.

We tested this library with files from few MB to ~500GB in total size.

### Is it really fast?

Yes. On Samsung EVO 840 / 850 with modern CPU you could expect about 400-500MB/s for delta generation.

### Thanks

Michael Samuel (https://github.com/therealmik/pyrdiff)

### License 

GPLv2, author: Pavel Odintsov, pavel.odintsov@gmail.com

