# Demo data for screenshots

`main.tf` — `dangerous` policy flagged (wildcard Action + Resource, no
Condition); `scoped` policy not flagged.

## How to get the screenshot

1. `./gradlew runIde` from `terraform-iam-wildcard-companion`, open
   this `demo/` folder as the project.
2. Full Screen, open `main.tf` — warnings should appear on the
   `dangerous` resource's statement lines but not on `scoped`.
3. Screenshot with both resources visible, save into
   `terraform-iam-wildcard-companion/docs/screenshots/`. Close the
   sandbox.
