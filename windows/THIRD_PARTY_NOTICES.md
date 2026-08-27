# Windows portable runtime notices

`tracefox.cmd start` downloads or uses unmodified binary distributions from the
following projects:

- Python 3.11.9 embeddable distribution, Python Software Foundation License:
  <https://www.python.org/downloads/release/python-3119/>
- VictoriaMetrics 1.106.1, Apache License 2.0:
  <https://github.com/VictoriaMetrics/VictoriaMetrics/releases/tag/v1.106.1>
- Grafana OSS 12.4.0, GNU Affero General Public License v3.0:
  <https://github.com/grafana/grafana/tree/v12.4.0>

The exact download URLs and SHA256 digests are pinned in
`windows/runtime-manifest.psd1`. The upstream archives retain their own license
and notice files. TraceFox does not modify these third-party binaries.
