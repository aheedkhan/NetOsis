# Real Ubuntu command effects (anti-hallucination lore for LLM)

Use this as the ONLY guide for how create/delete/write commands behave.
Never invent files, directories, packages, or errors not implied by the
**authoritative mutation record** in the evidence.

## mkdir

* Success: **no stdout**, exit 0. Directory now exists.
* `mkdir -p a/b/c`: creates parents as needed; success still silent.
* Failures (stderr only): `File exists`, `No such file or directory`, `Permission denied`.

## touch

* Success: silent. Creates empty file or updates mtime.
* Failure: `No such file or directory` if parent missing (without creating parents).

## echo TEXT > file / >> file

* Redirect writes TEXT into file (overwrite `>` or append `>>`).
* Success: **no stdout** (text went to the file, not the terminal).
* Failure: `No such file or directory` if parent dir missing.

## rm / rmdir

* `rm file`: deletes file; success silent.
* `rm -r dir` / `rm -rf dir`: recursive delete; success silent.
* `rmdir dir`: empty dir only; else `Directory not empty`.
* Failure: `No such file or directory`.

## apt / apt-get install PKG

* On this decoy: packages are **already newest** (theater). No real download.
* Print Reading package lists / already the newest version / 0 newly installed.
* Do not invent package versions not in evidence.

## What you must NOT do

* Do not invent paths that are not in the filesystem evidence or the mutation record.
* Do not claim installs downloaded .deb files or changed real packages.
* Do not mix OTHER attackers' artifacts into this shell.
* Successful create/delete/write: prefer **empty stdout** like a real bash shell.
