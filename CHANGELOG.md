<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Terraform IAM Wildcard Companion Changelog

## [Unreleased]

## [0.2.0]

### Fixed

- An `Effect = "Deny"` statement was flagged as an overly permissive
  wildcard the same as `Effect = "Allow"` -- but `Deny` on
  `Action = "*"`/`Resource = "*"` with no `Condition` is the most
  restrictive statement possible (AWS's own documented "quarantine"
  pattern for isolating a compromised principal), the opposite of a
  least-privilege violation. `Deny` statements are never flagged now.
- `Statement` as a single object (`Statement = {...}`), not wrapped in
  a list, was never scanned at all -- a real false negative, since AWS
  IAM allows both forms when there's exactly one statement and real
  Terraform code uses the object form for simple single-permission
  policies. Both forms are handled now.

## [0.1.0]

### Added

- Warning on an IAM policy statement (Terraform
  `aws_iam_policy`/`aws_iam_role_policy` resource's
  `jsonencode({...})`) whose Action or Resource is `"*"` with no
  Condition to scope it.
- Handles both string and list forms of Action/Resource, via
  brace/bracket-balanced scanning of the HCL literal (not a JSON
  parser).

[Unreleased]: https://github.com/GapHunterLabs/terraform-iam-wildcard-companion/compare/0.2.0...HEAD
[0.2.0]: https://github.com/GapHunterLabs/terraform-iam-wildcard-companion/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/GapHunterLabs/terraform-iam-wildcard-companion/commits/0.1.0
