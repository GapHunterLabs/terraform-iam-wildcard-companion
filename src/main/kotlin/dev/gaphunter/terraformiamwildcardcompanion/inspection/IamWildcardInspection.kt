package dev.gaphunter.terraformiamwildcardcompanion.inspection

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import dev.gaphunter.terraformiamwildcardcompanion.detect.HclJsonEncodeScanner
import dev.gaphunter.terraformiamwildcardcompanion.model.IamWildcardHit
import dev.gaphunter.terraformiamwildcardcompanion.model.WildcardField
import dev.gaphunter.terraformiamwildcardcompanion.review.ReviewPrompt

/**
 * Flags an IAM policy statement (inside a Terraform
 * `aws_iam_policy`/`aws_iam_role_policy` resource's `jsonencode({...})`
 * block) whose `Action` or `Resource` is `"*"` with no `Condition`
 * scoping it down -- the most direct violation of least-privilege,
 * a real vector for privilege escalation in cloud incidents, and a
 * chequeo dedicado in tfsec (`no-policy-wildcards`) and Tenable.
 *
 * Runs via `checkFile` (whole-file text scan), same reasoning as
 * `k8s-resource-limit-companion`'s `MissingResourceLimitInspection`:
 * detection is plain-text scanning of an HCL literal, not a PSI walk
 * of a specific grammar -- the platform has no bundled HCL/Terraform
 * PSI to depend on.
 */
class IamWildcardInspection : LocalInspectionTool() {

    companion object {
        const val MAX_FILE_LENGTH = 500_000
        private val TF_FILE_NAME = Regex("""^[^.]+\.tf$""", RegexOption.IGNORE_CASE)
    }

    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val virtualFile = file.virtualFile ?: return null
        if (!TF_FILE_NAME.matches(virtualFile.name)) return null

        val text = file.text
        if (text.length > MAX_FILE_LENGTH) return null

        val hits = HclJsonEncodeScanner.scan(text)
        if (hits.isEmpty()) return null

        val document = file.viewProvider.document ?: return null
        val problems = mutableListOf<ProblemDescriptor>()

        for ((lineNumber, lineHits) in hits.groupBy { document.getLineNumber(it.statementStartOffset) }) {
            if (lineNumber !in 0 until document.lineCount) continue
            val lineStartOffset = document.getLineStartOffset(lineNumber)
            val lineEndOffset = document.getLineEndOffset(lineNumber)
            val anchor = leafElementAt(file, lineStartOffset) ?: continue
            val anchorStart = anchor.textRange.startOffset
            val relativeRange = TextRange(
                (lineStartOffset - anchorStart).coerceAtLeast(0),
                (lineEndOffset - anchorStart).coerceAtMost(anchor.textLength),
            )
            if (relativeRange.startOffset >= relativeRange.endOffset) continue

            problems += manager.createProblemDescriptor(
                anchor,
                relativeRange,
                messageFor(lineHits),
                ProblemHighlightType.GENERIC_ERROR_OR_WARNING,
                isOnTheFly,
            )

            ReviewPrompt.recordHit(file.project, "${virtualFile.path}:$lineNumber")
        }

        return if (problems.isEmpty()) null else problems.toTypedArray()
    }

    private fun messageFor(hits: List<IamWildcardHit>): String {
        val fields = hits.map { it.field }.distinct().joinToString(" and ") {
            when (it) {
                WildcardField.ACTION -> "Action"
                WildcardField.RESOURCE -> "Resource"
            }
        }
        return "IAM policy statement has $fields set to \"*\" with no Condition to scope it -- " +
            "a direct violation of least-privilege, a real vector for privilege escalation"
    }

    private fun leafElementAt(file: PsiFile, startOffset: Int): PsiElement? {
        if (startOffset < 0 || startOffset >= file.textLength) return null
        var element = file.findElementAt(startOffset) ?: return file
        while (element.firstChild != null) {
            element = element.firstChild
        }
        return element
    }
}
