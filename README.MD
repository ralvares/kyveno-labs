# Kyverno Labs 

## Getting Quay Vulnerability Metadata 
```
wget https://raw.githubusercontent.com/ralvares/kyveno-labs/main/get-vulnerability-results.sh
chmod +x get-vulnerability-results.sh

$./get-vulnerability-results.sh repository/image label
```

The results are stored on the scan.json file

## Kyverno and Cosign 

The Kyverno verifyImages rule uses Cosign to verify container image signatures and in-toto attestations stored in an OCI registry.
An image can be signed with multiple signatures, for example at the organization level and at the project level.

### Generate cosign key

To sign images, install Cosign and generate a public-private key pair.

```
cosign generate-key-pair
```

Next, use the cosign sign command and specifying the private key in the -key command line argument.

```
cosign sign --key cosign.key quay.io/repository/image:label
```
### Verifying Image Attestations

Container image signatures prove that the image was signed by the holder of a matching private key, However, signatures do not provide additional data.
An attestation is metadata attached to software artifacts like images. Signed attestations provide verifiable information.

The in-toto attestation format provides a flexible scheme for metadata such as repository and build environment details, vulnerability scan reports, test results, code review reports, or any other information that is used to verify image integrity. Each attestation contains a signed statement with a predicateType and a predicate. The imageVerify rule can contain one or more attestation checks that verify the contents of the predicate.

### Adding Quay vulnerability metadata (scan.json) and Signing attestations using cosign.

To sign attestations, use the cosign attest command. This command will sign your attestations and publish them to the OCI registry.

```
cosign attest quay.io/repository/image:label --key cosign.key --predicate scan.json --type https://quay.io/api/v1/
```

## Kyverno Policy to block any container image that Contain High or Critical Vulnerabilities

```
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: check-vulnerabilities
spec:
  validationFailureAction: enforce
  webhookTimeoutSeconds: 10
  failurePolicy: Fail
  rules:
    - name: Contain-High-or-Critical-Vulnerabilities
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "quay.io/repository/image:*"
        attestors:
        - entries:
          - keys:
              publicKeys: |-
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6MBoAFnYBoFX4Jnbsv3UghAJY+Eh
                T2qxR4zpI58cRhDtlFJzf/4fuwQOe2K/Y2HwmgP7k5cRas3vc92TmNTPgg==
                -----END PUBLIC KEY-----                
        attestations:
        - predicateType: https://quay.io/api/v1/
          conditions:
          - all:
            - key: "{{data.Layer.Features[].Vulnerabilities[].Severity | (contains(@, 'High') || contains(@, 'Critical'))}}"
              operator: Equals
              value: False
```
