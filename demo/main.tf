resource "aws_iam_policy" "dangerous" {
  name = "dangerous-policy"

  # Flagged: both Action and Resource are wildcards, no Condition.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "scoped" {
  name = "scoped-policy"

  # Not flagged: specific action and resource.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::my-app-bucket/*"
      }
    ]
  })
}
