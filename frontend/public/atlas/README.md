## Atlas map data

`world-110m.topo.json` — Natural Earth 1:110m country boundaries, public domain.

Source: https://github.com/topojson/world-atlas (countries-110m.json).
Mirror used for download: https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json

The file's `objects.countries.geometries[].id` holds **UN M49 numeric** country
codes. IntelFeed's `Country.iso_code` uses ISO 3166-1 alpha-3, so we map between
the two with the table in `frontend/src/utils/mapTopology.ts` (`NUMERIC_TO_ALPHA3`).
