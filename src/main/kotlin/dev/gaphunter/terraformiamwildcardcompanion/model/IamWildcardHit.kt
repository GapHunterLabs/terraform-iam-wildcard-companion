package dev.gaphunter.terraformiamwildcardcompanion.model

enum class WildcardField {
    ACTION,
    RESOURCE,
}

/** One IAM policy statement (inside a `jsonencode({...})` block) whose Action or Resource is `"*"` with no Condition to scope it. */
data class IamWildcardHit(
    val field: WildcardField,
    /** Offset within the whole file text where this statement's opening `{` begins -- the anchor for the warning. */
    val statementStartOffset: Int,
)
