<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# Terraform IAM Wildcard Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Warning on an IAM policy statement (Terraform
  `aws_iam_policy`/`aws_iam_role_policy` resource's
  `jsonencode({...})`) whose Action or Resource is `"*"` with no
  Condition to scope it.
- Handles both string and list forms of Action/Resource, via
  brace/bracket-balanced scanning of the HCL literal (not a JSON
  parser).

[Unreleased]: https://github.com/GapHunterLabs/terraform-iam-wildcard-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/terraform-iam-wildcard-companion/commits/0.1.0
