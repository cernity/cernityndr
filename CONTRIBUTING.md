# Contributing to Cernity

Thanks for your interest in Cernity. This is a source-available project stewarded by
the Cernity Project, so a few things work differently from a typical open-source
repo.

## License of contributions

Cernity is licensed under the **PolyForm Perimeter License 1.0.1** (see
[LICENSE](LICENSE)). By submitting a contribution (a pull request, patch, or any
change), you agree that:

1. You have the right to submit it.
2. Your contribution is provided under the same PolyForm Perimeter License that
   covers the project.
3. You grant the Cernity Project a perpetual, irrevocable, royalty-free license to
   use, modify, sublicense, and **relicense** your contribution as part of Cernity —
   including under different or commercial license terms.

Point 3 keeps ownership of the combined work with the Cernity Project, so Cernity
can be dual-licensed or relicensed in the future without having to track down every
contributor. If you cannot agree to this, please don't submit code — an issue or a
discussion is still very welcome.

A lightweight Contributor License Agreement (CLA) check may be added to pull
requests before the first outside contribution is merged.

## Scope — contribute to Cernity's own code

Contributions apply to Cernity's own services, detectors, contracts, shared
libraries, and docs. Cernity also uses independent third-party software (Suricata,
Zeek, Fluent Bit, Redpanda, Redis, ClickHouse, MinIO, OpenSearch, Python libraries)
under their own licenses — see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
Don't vendor or relicense third-party code into the repository.

## How to contribute

- **Issues and discussion:** always open, no agreement needed.
- **Bug fixes and small improvements:** open a PR against `main`. Keep it focused.
- **New detectors or services:** open an issue first to align on the contract and
  where it fits in the pipeline before you build.

## Ground rules

- Every service is small and single-purpose, communicates over the bus, and is
  independently testable. Match that shape.
- Wire and store schemas are pinned in `contracts/` — the public interface. Don't
  change a schema without updating `contracts/` and its tests.
- Include tests. The detector tier is validated by a replay/diff harness against
  labeled traffic; new detection logic needs a test that fails if it breaks.
- No hardcoded environment specifics (IPs, hostnames, secrets). Everything is
  configured through environment variables or config topics.

## Trademark

Contributing code does not grant any right to the "Cernity" name. See
[TRADEMARK.md](TRADEMARK.md).
