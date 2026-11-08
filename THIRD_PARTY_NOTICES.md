# Third-party notices

The foundation contains original project instructions and code. No upstream skill
text, scanner binary, ruleset or dependency implementation is vendored. The MIT
license applies to original project material, not to linked external projects.

`docs/SOURCE_REVIEW.md` and `config/sources.json` record research candidates and
source links. Referencing a candidate does not install it or relicense its content.

Before copying or distributing upstream content, record its repository, exact
revision, adopted paths, license text, required attribution, local modifications
and compatibility decision here. Inspect license scope at the adopted paths:
repository-level metadata alone may be insufficient. Share-alike and copyleft
material must not be represented as MIT merely because it is included in this
project. Integration may use an adapter without redistribution where appropriate.

## Optional k6 adapter

The M5 adapter invokes a separately acquired current official Grafana k6 native
binary. [k6](https://github.com/grafana/k6) is licensed under
[AGPL-3.0](https://github.com/grafana/k6/blob/master/LICENSE.md); this repository
includes neither its binary nor copied implementation. Generated broker scripts
and the Python adapter are original project code. Inspect the exact acquired
release license and distribution obligations before redistribution. The project
MIT license does not relicense k6. Official version-matched option/scenario
documentation informs the fixed invocation and compatibility checks.
