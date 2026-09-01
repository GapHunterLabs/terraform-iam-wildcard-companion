package dev.gaphunter.terraformiamwildcardcompanion.detect

import dev.gaphunter.terraformiamwildcardcompanion.model.IamWildcardHit
import dev.gaphunter.terraformiamwildcardcompanion.model.WildcardField

/**
 * Plain-text scanner for `resource "aws_iam_policy"`/
 * `resource "aws_iam_role_policy"` blocks whose `policy` attribute is
 * a `jsonencode({...})` call -- flags a statement whose `Action` or
 * `Resource` is `"*"` (or a list containing `"*"`) with no `Condition`
 * block scoping it down.
 *
 * **Not a JSON parser** -- despite the name `jsonencode`, its argument
 * is an HCL expression (a map/list literal using `=` and unquoted or
 * quoted keys), evaluated to a JSON STRING only at Terraform apply
 * time. The source text itself is HCL object/list syntax, which this
 * scanner walks directly via brace/bracket balancing
 * ([BalancedBraceMatcher]) rather than needing a real HCL grammar or a
 * JSON parser -- deliberately, since the platform has no PSI for
 * either inside a Kotlin-only plugin.
 *
 * **v0.1 scope, stated honestly:** only the direct HCL pattern
 * (`jsonencode({...})` embedded directly in the resource block) --
 * never follows a policy loaded from an external `.json` file via
 * `file(...)`.
 */
object HclJsonEncodeScanner {

    private val RESOURCE_HEADER = Regex("""resource\s+"(aws_iam_policy|aws_iam_role_policy)"\s+"[\w-]+"\s*\{""")
    private val JSONENCODE_CALL = Regex("""policy\s*=\s*jsonencode\s*\(""")
    private val STATEMENT_KEY = Regex(""""?Statement"?\s*=\s*\[""")
    private val ACTION_STRING = Regex(""""?Action"?\s*=\s*"([^"]*)"""")
    private val ACTION_LIST = Regex(""""?Action"?\s*=\s*\[([^]]*)]""")
    private val RESOURCE_STRING = Regex(""""?Resource"?\s*=\s*"([^"]*)"""")
    private val RESOURCE_LIST = Regex(""""?Resource"?\s*=\s*\[([^]]*)]""")
    private val CONDITION_KEY = Regex(""""?Condition"?\s*=\s*\{""")

    fun scan(text: String): List<IamWildcardHit> {
        val hits = mutableListOf<IamWildcardHit>()
        for (resourceMatch in RESOURCE_HEADER.findAll(text)) {
            val resourceBraceStart = resourceMatch.range.last // index of the resource block's own '{'
            val resourceBraceEnd = BalancedBraceMatcher.findMatchingClose(text, resourceBraceStart, '{', '}') ?: continue
            val resourceBody = text.substring(resourceBraceStart, resourceBraceEnd + 1)
            val resourceBodyOffset = resourceBraceStart

            hits += hitsInResourceBody(text, resourceBody, resourceBodyOffset)
        }
        return hits
    }

    private fun hitsInResourceBody(fullText: String, resourceBody: String, resourceBodyOffset: Int): List<IamWildcardHit> {
        val jsonencodeMatch = JSONENCODE_CALL.find(resourceBody) ?: return emptyList()
        // Find the '{' that opens the object literal passed to jsonencode(...) --
        // the first non-whitespace character after the call's own '('.
        var objStart = jsonencodeMatch.range.last + 1
        while (objStart < resourceBody.length && resourceBody[objStart].isWhitespace()) objStart++
        if (objStart >= resourceBody.length || resourceBody[objStart] != '{') return emptyList()

        val objStartAbs = resourceBodyOffset + objStart
        val objEndAbs = BalancedBraceMatcher.findMatchingClose(fullText, objStartAbs, '{', '}') ?: return emptyList()
        val policyObject = fullText.substring(objStartAbs, objEndAbs + 1)
        val policyObjectOffset = objStartAbs

        return hitsInPolicyObject(fullText, policyObject, policyObjectOffset)
    }

    private fun hitsInPolicyObject(fullText: String, policyObject: String, policyObjectOffset: Int): List<IamWildcardHit> {
        val statementMatch = STATEMENT_KEY.find(policyObject) ?: return emptyList()
        val listStart = statementMatch.range.last // index of the '['
        val listStartAbs = policyObjectOffset + listStart
        val listEndAbs = BalancedBraceMatcher.findMatchingClose(fullText, listStartAbs, '[', ']') ?: return emptyList()

        val hits = mutableListOf<IamWildcardHit>()
        var i = listStartAbs + 1
        while (i < listEndAbs) {
            val c = fullText[i]
            if (c == '{') {
                val stmtEnd = BalancedBraceMatcher.findMatchingClose(fullText, i, '{', '}')
                if (stmtEnd == null || stmtEnd > listEndAbs) break
                val statementText = fullText.substring(i, stmtEnd + 1)
                hits += hitsInStatement(statementText, i)
                i = stmtEnd + 1
            } else {
                i++
            }
        }
        return hits
    }

    private fun hitsInStatement(statementText: String, statementStartOffset: Int): List<IamWildcardHit> {
        val hasCondition = CONDITION_KEY.containsMatchIn(statementText)
        if (hasCondition) return emptyList()

        val hits = mutableListOf<IamWildcardHit>()
        if (fieldHasWildcard(statementText, ACTION_STRING, ACTION_LIST)) {
            hits += IamWildcardHit(WildcardField.ACTION, statementStartOffset)
        }
        if (fieldHasWildcard(statementText, RESOURCE_STRING, RESOURCE_LIST)) {
            hits += IamWildcardHit(WildcardField.RESOURCE, statementStartOffset)
        }
        return hits
    }

    private fun fieldHasWildcard(statementText: String, stringForm: Regex, listForm: Regex): Boolean {
        stringForm.find(statementText)?.let { return it.groupValues[1] == "*" }
        listForm.find(statementText)?.let { match ->
            val entries = match.groupValues[1].split(",").map { it.trim().trim('"') }
            return entries.any { it == "*" }
        }
        return false
    }
}
