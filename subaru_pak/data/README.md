# Pack database

This package does **not** ship Subaru's `Pack File Database_*.csv`. That file is
Subaru's property (it holds the per-pack RC2 keys and vehicle metadata) and is
distributed with FlashWrite, not here.

The library finds it on its own at runtime:

1. an explicit `--db <path>` (CLI) or `database=` argument;
2. a copy dropped in this folder as `Pack_File_Database_N_AMERICA.csv`
   (it will be picked up and, if you build binaries, bundled — do that only for
   your own use);
3. a local FlashWrite installation — see `subaru_pak.keys.installed_databases`.

Without any of these, `subaru-pak` still converts a pak if you supply the key
directly with `--key`, or recovers it with `subaru-pak recover`.
