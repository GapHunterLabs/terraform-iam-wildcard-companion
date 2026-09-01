package dev.gaphunter.terraformiamwildcardcompanion.inspection

import com.intellij.testFramework.fixtures.BasePlatformTestCase

class IamWildcardInspectionTest : BasePlatformTestCase() {

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(IamWildcardInspection::class.java)
    }

    fun `test a wildcard statement with no Condition produces a warning`() {
        myFixture.configureByText(
            "main.tf",
            """
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
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.any { it.description?.contains("least-privilege") == true })
    }

    fun `test a scoped statement produces no warning`() {
        myFixture.configureByText(
            "main2.tf",
            """
            resource "aws_iam_policy" "example" {
              policy = jsonencode({
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = "s3:GetObject"
                    Resource = "arn:aws:s3:::my-bucket/*"
                  }
                ]
              })
            }
            """.trimIndent(),
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("least-privilege") == true })
    }

    fun `test a non-tf file is never scanned`() {
        myFixture.configureByText(
            "Notes.java",
            "String x = \"Action = \\\"*\\\", Resource = \\\"*\\\"\";",
        )
        val highlights = myFixture.doHighlighting()
        assertTrue(highlights.none { it.description?.contains("least-privilege") == true })
    }
}
