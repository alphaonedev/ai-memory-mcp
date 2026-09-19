#!/usr/bin/env python3
"""Render #3636's guide using the messaging atlas's existing site chrome.

Requires Python-Markdown. Run from any directory after editing the Markdown.
"""
from pathlib import Path
import re
import markdown

root = Path(__file__).resolve().parents[1]
atlas = (root / 'docs/a2a-messaging.html').read_text()
head = atlas[:atlas.index('</nav>') + len('</nav>')]
head = head.replace('A2A Messaging', 'A2A Integration').replace('a2a-messaging.html', 'a2a-integration.html', 1)
head = re.sub(r'<meta name="description"[^>]*>', '<meta name="description" content="Integrate any AI agent with the shipped ai-memory v1.0.0 wake plane: enrolment, receiving, sending, shell loops, SDKs and troubleshooting.">', head)
head = head.replace('class="current" href="a2a-messaging.html"', 'href="a2a-messaging.html"')
head = head.replace('<a href="a2a-integration.html">Integrate an Agent', '<a class="current" href="a2a-integration.html">Integrate an Agent')
# Reuse atlas variables, spacing, snippet and table conventions.
layout = (root / 'docs/_layouts/doc.html').read_text()
main_styles = layout[layout.index('main{'):layout.index('/* rouge')]
head = head.replace('</style>', main_styles + '</style>')
guide = (root / 'docs/a2a-integration.md').read_text()
body = markdown.markdown(guide, extensions=['fenced_code', 'tables', 'toc'])
# Repository-relative SDK links must work from Pages too.
body = body.replace('../sdk/', 'https://github.com/alphaonedev/ai-memory-mcp/blob/main/sdk/')
hero = re.search(r'<h1[^>]*>(.*?)</h1>', body, re.S)
if hero is None:
    raise ValueError('Integration guide must have a title')
body = body[:hero.start()] + body[hero.end():]
header = '<header class="hero"><h1>' + hero[1] + '</h1></header>'
footer = atlas[atlas.index('<footer>'):]
(root / 'docs/a2a-integration.html').write_text(head + '\n' + header + '\n<main>\n' + body + '\n</main>\n' + footer)
