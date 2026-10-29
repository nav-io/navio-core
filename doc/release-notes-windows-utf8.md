Windows
-------

- Windows binaries now embed an application manifest that sets UTF-8 as the
  process code page, so non-ASCII paths (for example a `-datadir` or wallet
  path) and command-line arguments work and print correctly instead of being
  mangled through the system ANSI code page.
- Windows versions before Windows 10 version 1903 ignore the setting and keep
  the old behaviour.
