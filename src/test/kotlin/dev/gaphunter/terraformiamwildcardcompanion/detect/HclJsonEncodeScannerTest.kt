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
