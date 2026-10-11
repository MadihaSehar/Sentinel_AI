# Sample Report

These files are a ready-made example of SentinelAI's report output, generated
from fictional findings against `example.com` (the IANA-reserved documentation
domain — nothing here points at a real host).

| File | What it is |
|------|------------|
| `sentinelai-sample-report.html` | Standalone HTML report (open in any browser) |
| `sentinelai-sample-report.pdf`  | The same report exported to PDF |

Both are produced by `app.reports.build_report_html` / `build_report_pdf`, the
exact code path behind the `/api/reports/*` endpoints. To regenerate them:

```bash
cd backend
python -c "from app.reports import build_sample_report, build_report_html, build_report_pdf; \
d=build_sample_report(); \
open('../docs/sample-report/sentinelai-sample-report.html','w').write(build_report_html(d)); \
open('../docs/sample-report/sentinelai-sample-report.pdf','wb').write(build_report_pdf(d))"
```
