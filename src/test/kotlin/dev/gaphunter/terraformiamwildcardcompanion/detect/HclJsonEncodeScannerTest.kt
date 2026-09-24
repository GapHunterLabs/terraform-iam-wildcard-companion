package dev.gaphunter.terraformiamwildcardcompanion.detect

import dev.gaphunter.terraformiamwildcardcompanion.model.WildcardField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HclJsonEncodeScannerTest {

    @Test
    fun `flags a statement with Action wildcard and no Condition`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              name = "example"
              policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "arn:aws:s3:::my-bucket/*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(1, hits.size)
        assertEquals(WildcardField.ACTION, hits[0].field)
    }

    @Test
    fun `flags a statement with Resource wildcard in list form`() {
        val hcl = """
            resource "aws_iam_role_policy" "example" {
              name = "example"
              role = aws_iam_role.example.id
              policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = ["s3:GetObject"]
                    Resource = ["*"]
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(1, hits.size)
        assertEquals(WildcardField.RESOURCE, hits[0].field)
    }

    @Test
    fun `flags both Action and Resource wildcard as two separate hits`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(2, hits.size)
        assertTrue(hits.any { it.field == WildcardField.ACTION })
        assertTrue(hits.any { it.field == WildcardField.RESOURCE })
    }

    @Test
    fun `does not flag a wildcard statement that has a Condition block`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                    Condition = {
                      StringEquals = {
                        "aws:PrincipalOrgID" = "o-1234567890"
                      }
                    }
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertTrue(hits.isEmpty())
    }

    @Test
    fun `does not flag an explicit Deny statement even with unscoped wildcards`() {
        // A real, common AWS pattern (AWS's own documented "quarantine" policy
        // for isolating a compromised IAM principal): Effect = "Deny", Action
        // and Resource both "*", no Condition. This is the MOST restrictive
        // statement possible, the opposite of overly permissive -- flagging
        // it as a privilege-escalation risk would be a real false positive on
        // one of the most common security guardrail patterns in practice.
        val hcl = """
            resource "aws_iam_policy" "quarantine" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Deny"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertTrue("a Deny statement must never be flagged as overly permissive", hits.isEmpty())
    }

    @Test
    fun `still flags an Allow statement in a policy that also has an unrelated Deny statement`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Deny"
                    Action   = "*"
                    Resource = "*"
                    Condition = {
                      StringNotEquals = { "aws:RequestedRegion" = "us-east-1" }
                    }
                  },
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(2, hits.size) // the Allow statement's Action AND Resource, not the Deny one
    }

    @Test
    fun `does not flag a scoped statement with specific action and resource`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = ["s3:GetObject", "s3:PutObject"]
                    Resource = "arn:aws:s3:::my-bucket/*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertTrue(hits.isEmpty())
    }

    @Test
    fun `handles multiple statements, flagging only the dangerous one`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "s3:GetObject"
                    Resource = "arn:aws:s3:::my-bucket/*"
                  },
                  {
                    Effect   = "Allow"
                    Action   = "*"
                    Resource = "*"
                  }
                ]
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(2, hits.size) // the second statement's Action AND Resource
        assertTrue(hits.all { it.statementStartOffset > hcl.indexOf("s3:GetObject") })
    }

    @Test
    fun `flags a wildcard in a single-statement-object policy, not wrapped in a list`() {
        // AWS IAM policy JSON allows "Statement" to be a single object
        // instead of an array when there's exactly one statement -- both
        // forms are valid and real Terraform code uses the object form for
        // simple single-permission policies. Missing this would be a real
        // false negative (a risky policy going completely undetected), the
        // more dangerous direction of error for a security scanner.
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Version = "2012-10-17"
                Statement = {
                  Effect   = "Allow"
                  Action   = "*"
                  Resource = "*"
                }
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertEquals(2, hits.size)
        assertTrue(hits.any { it.field == WildcardField.ACTION })
        assertTrue(hits.any { it.field == WildcardField.RESOURCE })
    }

    @Test
    fun `does not flag a scoped single-statement-object policy`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = {
                  Effect   = "Allow"
                  Action   = "s3:GetObject"
                  Resource = "arn:aws:s3:::my-bucket/*"
                }
              })
            }
        """.trimIndent()

        val hits = HclJsonEncodeScanner.scan(hcl)

        assertTrue(hits.isEmpty())
    }

    @Test
    fun `ignores a resource that is not an IAM policy`() {
        val hcl = """
            resource "aws_s3_bucket" "example" {
              bucket = "my-bucket"
            }
        """.trimIndent()

        assertTrue(HclJsonEncodeScanner.scan(hcl).isEmpty())
    }

    @Test
    fun `ignores a policy attribute that is not jsonencode`() {
        val hcl = """
            resource "aws_iam_policy" "example" {
              policy = file("policy.json")
            }
        """.trimIndent()

        assertTrue(HclJsonEncodeScanner.scan(hcl).isEmpty())
    }
}
