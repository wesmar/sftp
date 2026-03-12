SFTPplug - szybka instalacja
============================

1) Rozpakuj ZIP do dowolnego folderu.
2) Kliknij dwukrotnie install_sftp_plugin.cmd.
3) Po instalacji uruchom ponownie Total Commandera.

Co robi instalator:
- wykrywa katalog Total Commandera,
- kopiuje oba pliki pluginu do:
  Plugins\WFX\SFTPplug\sftpplug.wfx
  Plugins\WFX\SFTPplug\sftpplug.wfx64
- kopiuje skrypt PHP Agenta do katalogu pluginu:
  sftp.php (wersja biezaca, zalecana)
- ustawia wpis "sftp=..." w wincmd.ini, sekcja [FileSystemPlugins].
- ustawia wpis "sftp=1" w sekcji [FileSystemPlugins64].

Uwagi:
- Jezeli Total Commander jest portable, instalator moze poprosic o reczne podanie sciezki.
- Jezeli plugin wymaga zewnetrznych bibliotek DLL (libssh2/ssl/crypto),
  umiesc je w tym samym folderze co instalator przed uruchomieniem.
