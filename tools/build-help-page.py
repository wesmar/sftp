# Folds the help sources into one self-contained page.
#
# One file means Ctrl+F searches every topic at once, which is the single
# thing a CHM gave us that a folder of pages does not.
import html
import os
import re
import sys

SRC = 'src/help'
OUT = sys.argv[1] if len(sys.argv) > 1 else 'sftpplug-help.html'

# index.html lists the topics in reading order, so it decides the order here
# too — one file to keep straight instead of a separate table of contents.
index = open(os.path.join(SRC, 'index.html'), encoding='utf-8',
             errors='surrogateescape').read()
order = ['index.html'] + re.findall(r'(?i)href="([A-Za-z0-9._-]+\.html)"', index)
seen, pages = set(), []
for f in order:
    f = f.strip()
    if f and f not in seen and os.path.exists(os.path.join(SRC, f)):
        seen.add(f)
        pages.append(f)

# anything index.html does not link still ships, appended in name order
for f in sorted(os.listdir(SRC)):
    if f.endswith('.html') and f not in seen:
        pages.append(f)

sections = []
for f in pages:
    raw = open(os.path.join(SRC, f), encoding='utf-8', errors='surrogateescape').read()
    stem = os.path.splitext(f)[0]

    m = re.search(r'(?is)<title>(.*?)</title>', raw)
    title = html.unescape(m.group(1).strip()) if m else stem

    m = re.search(r'(?is)<body[^>]*>(.*?)</body>', raw)
    body = m.group(1) if m else raw

    # the page's own <h1> becomes the section heading, so drop the duplicate
    body = re.sub(r'(?is)^\s*<h1[^>]*>.*?</h1>', '', body, count=1)

    sections.append((stem, title, body.strip()))

ids = {stem for stem, _, _ in sections}


def relink(match):
    target, anchor = match.group(1), match.group(2) or ''
    stem = os.path.splitext(target)[0]
    if anchor:                      # a link into a heading keeps that heading's id
        return 'href="#' + anchor.lstrip('#') + '"'
    if stem in ids:
        return 'href="#' + stem + '"'
    return match.group(0)


parts = []
for stem, title, body in sections:
    body = re.sub(r'href="([a-zA-Z0-9._-]+\.html)(#[^"]*)?"', relink, body)
    parts.append(
        '<section id="{0}">\n<h1>{1}</h1>\n{2}\n</section>'.format(
            stem, html.escape(title), body))

nav = '\n'.join(
    '<li><a href="#{0}">{1}</a></li>'.format(stem, html.escape(title))
    for stem, title, _ in sections)

CSS = """
:root {
  --bg: #ffffff; --fg: #1b1f24; --muted: #5b6570;
  --accent: #0b4f9c; --line: #d9dee4; --soft: #f4f6f9;
  --warn: #b00020; --ok: #137333;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181d; --fg: #dfe4ea; --muted: #97a3b0;
    --accent: #6fb2ff; --line: #2b323a; --soft: #1b2027;
    --warn: #ff8a8a; --ok: #7ddc9a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.65 "Segoe UI", Tahoma, Arial, sans-serif;
}
#layout { display: flex; align-items: flex-start; }
#toc {
  position: sticky; top: 0; flex: 0 0 260px; height: 100vh; overflow-y: auto;
  padding: 22px 18px; border-right: 1px solid var(--line); background: var(--soft);
}
#toc h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .08em;
          color: var(--muted); margin: 0 0 12px; }
#toc ul { list-style: none; margin: 0; padding: 0; }
#toc li { margin: 0 0 2px; }
#toc a {
  display: block; padding: 5px 9px; border-radius: 6px;
  color: var(--fg); text-decoration: none; font-size: 14px;
}
#toc a:hover { background: var(--bg); }
#toc a.active { background: var(--accent); color: #fff; }
main { flex: 1 1 auto; min-width: 0; padding: 32px 40px 96px; max-width: 900px; }
section { scroll-margin-top: 16px; padding-bottom: 20px; }
section + section { border-top: 1px solid var(--line); padding-top: 28px; }
h1 { font-size: 26px; color: var(--accent); margin: 0 0 16px; }
h2 { font-size: 20px; color: var(--accent); margin: 26px 0 10px; }
h3 { font-size: 16px; color: var(--accent); margin: 20px 0 8px; }
a { color: var(--accent); }
code {
  background: var(--soft); border: 1px solid var(--line);
  padding: 1px 5px; border-radius: 4px;
  font: 13px/1.5 Consolas, "Cascadia Mono", monospace;
}
pre {
  background: var(--soft); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; overflow-x: auto;
}
pre code { background: none; border: 0; padding: 0; }
table { border-collapse: collapse; margin: 12px 0; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--line); padding: 6px 10px; text-align: left; }
th { background: var(--soft); }
.note { border-left: 3px solid var(--accent); background: var(--soft);
        padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
.warn { border-left: 3px solid var(--warn); background: var(--soft);
        padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
.ok   { border-left: 3px solid var(--ok); background: var(--soft);
        padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 12px 0; }
.small { color: var(--muted); font-size: .92em; }
ul li, ol li { margin-bottom: 4px; }
#hint { color: var(--muted); font-size: 12px; margin-top: 18px; line-height: 1.5; }
@media (max-width: 820px) {
  #layout { display: block; }
  #toc { position: static; height: auto; width: auto; flex: none;
         border-right: 0; border-bottom: 1px solid var(--line); }
  main { padding: 22px 18px 64px; }
}
"""

JS = """
// Mark the section currently on screen in the table of contents.
var links = {};
document.querySelectorAll('#toc a').forEach(function (a) {
  links[a.getAttribute('href').slice(1)] = a;
});
var current = null;
new IntersectionObserver(function (entries) {
  entries.forEach(function (e) {
    if (!e.isIntersecting) return;
    var a = links[e.target.id];
    if (!a || a === current) return;
    if (current) current.classList.remove('active');
    a.classList.add('active');
    current = a;
  });
}, { rootMargin: '-10% 0px -80% 0px' })
  .observe && document.querySelectorAll('section').forEach(function (s) {});
"""

# the observer needs a single instance; build it plainly rather than inline
JS = """
var links = {};
document.querySelectorAll('#toc a').forEach(function (a) {
  links[a.getAttribute('href').slice(1)] = a;
});
var current = null;
var io = new IntersectionObserver(function (entries) {
  entries.forEach(function (e) {
    if (!e.isIntersecting) return;
    var a = links[e.target.id];
    if (!a || a === current) return;
    if (current) current.classList.remove('active');
    a.classList.add('active');
    current = a;
  });
}, { rootMargin: '-10% 0px -80% 0px' });
document.querySelectorAll('section').forEach(function (s) { io.observe(s); });
"""

doc = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SFTPplug Help</title>
<style>{css}</style>
</head>
<body>
<div id="layout">
<nav id="toc">
<h2>Contents</h2>
<ul>
{nav}
</ul>
<p id="hint">Every topic is on this page, so <b>Ctrl+F</b> searches all of them at once.</p>
</nav>
<main>
{body}
</main>
</div>
<script>{js}</script>
</body>
</html>
""".format(css=CSS, nav=nav, body='\n\n'.join(parts), js=JS)

open(OUT, 'w', encoding='utf-8', newline='\n').write(doc)
print('{0}: {1} sections, {2:.0f} KB'.format(OUT, len(sections), len(doc.encode('utf-8')) / 1024))
