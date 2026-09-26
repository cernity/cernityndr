# Elasticsearch index template — `ndr-findings-*`

`ndr-findings-index-template.json` owns the mappings for the daily `ndr-findings-*` indices
(plan 010 Track B, B-U7 / review R11 + plan 008 §15.4). Without it, each daily index inferred its
own dynamic mappings — so `intel`/`geo` enrichment minted a field per indicator (exploding past
Elasticsearch's `total_fields` limit and dead-lettering new-field-bearing findings) and core fields
like `category`/`detector_id` came out as `text`+`keyword` on some days and `keyword` on others (the
mixed-mapping hazard that made `_agg_field` non-deterministic).

The template pins the queryable core fields (`finding_id`, `tenant_id`, `detector_id`,
`detector_version`, `category`, `state`, `severity`, `revision`, the date fields) to explicit types
and maps `intel`/`geo` as `flattened`, with `total_fields` capped at 2000.

## Apply

```sh
# creds via Vault (never printed); ES over the self-signed cert
curl -sk -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/json' \
  -X PUT "$ES_ENDPOINT/_index_template/ndr-findings" \
  --data-binary @ndr-findings-index-template.json
```

New indices created after this inherit the template; existing indices keep their mappings until they
roll over. `contracts/test_ndr_findings_template.py` validates the template's shape.
