# eGUAC: Extended Graph for Understanding Artifact Composition

eGuac is an extension of the GUAC tool. This enhancement allows the tool to support the eVEX file format and to leverage the GUAC graph to have a greater context of the security of a software supply chain.

## Quickstart

```bash
git clone https://github.com/Yato03/eGuac.git
cd eGuac
make container
make start-ent-db
```

## Supported input documents

- [CycloneDX](https://github.com/CycloneDX/specification)
- [Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [Deps.dev API](https://deps.dev/)
- [In-toto ITE6](https://github.com/in-toto/attestation)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard)
- [OSV](https://osv.dev/)
- [SLSA](https://github.com/slsa-framework/slsa)
- [SPDX](https://spdx.dev/specifications/)
- [CSAF/CSAF VEX](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [OpenVEX](https://github.com/openvex)
- [eVEX](https://github.com/GermanMT/vexgen/wiki/Extended-VEX-Spec-v0.1.0) **<-- New One**


## GraphQL backends

eGuac as well as GUAC supports different backends. The following shows how to run each one.

```bash
# With PostgreSQL
make start-ent-db

# With Redis
make start-redis-db

# With Tikv
make start-tikv-db

# With ArangoDB
make start-arango-db
```