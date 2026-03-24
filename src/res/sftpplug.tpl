; sftpplug.ini — SFTPplug configuration file
; This file is created automatically on first run.
; Edit values below to change plugin-wide defaults.
;
; Plugin-wide options go in the [Configuration] section.
; Each saved session is stored in its own [SessionName] section.

[Configuration]

; Language= overrides the UI language detected from Total Commander.
; Use this when:
;   - TC is set to a language not in the supported 15 (e.g. Finnish, Turkish,
;     Norwegian) — the plugin falls back to English; set Language= to the
;     closest available language instead.
;   - TC uses a custom/community language file the plugin cannot identify
;     (e.g. shows Chinese characters by mistake).
;
; You can also create a custom translation file: place language\fin.lng in the
; plugin directory and set Language=fin. See any built-in .lng file for the format.
;
; Built-in values (case-insensitive):
;   English, Polish, German, French, Spanish, Italian, Russian, Czech,
;   Hungarian, Japanese, Dutch, Portuguese (or pt-br), Romanian, Slovak,
;   Ukrainian, Chinese (or zh-cn)
; ISO two-letter codes also work: en, pl, de, fr, es, it, ru, cs, hu, ja, nl, ro, sk, uk
; Three-letter stems match the .lng filenames: pol, deu, fra, esp, ita, rus, hu, ja, nl, ro, sk, uk, chs
;
; Example — force English regardless of TC language:
;Language=English
;
; Example — force Polish:
;Language=Polish
