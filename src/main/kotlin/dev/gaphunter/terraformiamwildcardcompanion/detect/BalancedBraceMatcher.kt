package dev.gaphunter.terraformiamwildcardcompanion.detect

/**
 * Finds the index of the closing bracket that matches the opening
 * bracket at [openIndex] in [text] -- respects nested brackets of the
 * SAME type (so `{ a = { b = 1 } }` finds the outer `}`, not the
 * inner one) and skips over bracket characters that appear inside a
 * double-quoted string literal (so `{ a = "}" }` isn't confused by the
 * `}` inside the string). Handles a backslash-escaped quote inside the
 * string (`"a\"b"`) so it doesn't end the string early.
 *
 * Used for both `{`/`}` and `[`/`]` -- pass the matching pair via
 * [openChar]/[closeChar].
 */
object BalancedBraceMatcher {

    fun findMatchingClose(text: String, openIndex: Int, openChar: Char, closeChar: Char): Int? {
        if (openIndex !in text.indices || text[openIndex] != openChar) return null

        var depth = 0
        var inString = false
        var i = openIndex
        while (i < text.length) {
            val c = text[i]
            if (inString) {
                when (c) {
                    '\\' -> i++ // skip the escaped character entirely, whatever it is
                    '"' -> inString = false
                }
            } else {
                when (c) {
                    '"' -> inString = true
                    openChar -> depth++
                    closeChar -> {
                        depth--
                        if (depth == 0) return i
                    }
                }
            }
            i++
        }
        return null // unbalanced -- never guess, the caller treats null as "can't parse this"
    }
}
