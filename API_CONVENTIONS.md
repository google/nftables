# nftables API Conventions

This document outlines the API design conventions for the golang `nftables` package. As the library stabilizes towards a v1 release, all new API additions must follow these conventions, and we are working to refactor existing inconsistencies.

## 1. Optional Fields: Pointer vs. Zero Value

When mapping netlink attributes to Go structs, handling optional fields requires care to avoid the "zero-value trap", where it is impossible to distinguish between a field the user did not set, and a field explicitly set to the zero-value.

**Convention:**
*   **Use Pointers for Values where `0` is valid:** If the zero-value of the underlying type is a semantically meaningful value in netfilter (e.g., `0` for `ChainPriorityFilter` or `0` for `ChainPolicyDrop`), you **must** use a pointer (e.g., `*int32`, `*uint32`). This allows the package to distinguish between `nil` (unset) and an explicit pointer to `0`.
*   **Use Zero Values for Identifiers/Sizes:** Use regular types (zero values) for fields where `0` or `""` (empty string) naturally means "unset" or "invalid" (e.g., `ID`, `Handle`, `Name`).

## 2. Fetching Data: Verbs and Pluralization (List vs. Get)

**History:**
Historically, the golang `nftables` API has seen a mix of two different conventions:
1.  **Netlink Message Names:** The original implementation (e.g., `GetRule`) closely mirrored the underlying netlink message names (e.g., `NFT_MSG_GETRULE`).
2.  **`nft` CLI:** Later contributions (e.g., `ListTables`, `ListChain`) mapped directly to the `nftables` command-line interface (e.g., `nft list tables`, `nft list chain`), documented at the [official netfilter project manpage](https://www.netfilter.org/projects/nftables/manpage.html).

**Convention to Follow:**
Since golang `nftables` is a programmatic netlink wrapper rather than a CLI text generator, the API should align its verbs with standard Go programmatic conventions and the underlying netlink concepts (`GET`, `NEW`, `DEL`), rather than the `nft` CLI frontend.

*   **Fetching Single Items (`Get`):** Use `Get<SingularEntity>` to retrieve a specific item. This aligns with the netlink `NFT_MSG_GET...` commands without the dump flag.
    *   *Examples:* `GetTable`, `GetRuleByHandle`, `GetSet`.
    *   *To be refactored (currently match CLI):* `ListTable`, `ListChain` (should become `GetTable`, `GetChain`).
*   **Fetching Collections (`List`):** Use `List<PluralEntities>` when retrieving multiple items (which corresponds to netlink `NFT_MSG_GET...` with the `NLM_F_DUMP` flag).
    *   *Examples:* `ListTables`, `ListChains`.
    *   *To be refactored (currently match Netlink name but return slices):* `GetSets`, `GetRules` (should become `ListSets`, `ListRules`).

## 3. Modification Verbs

Operations that modify the ruleset should use consistent verbs indicating their behavior. Modification operations generally act on a singular entity unless they are batch element modifications.

**Convention:**
*   **`Add<Entity>`**: Creates or adds an entity.
*   **`Insert<Entity>`**: Inserts an entity at a specific position (used primarily for rules).
*   **`Replace<Entity>`**: Replaces an entity.
*   **`Del<Entity>`**: Deletes an entity. Returns an error if the entity *does not exist*.
*   **`Destroy<Entity>`**: Deletes an entity but *does not* return an error if it doesn't exist (requires kernel >= 6.3).
*   **`Flush<Entity>`**: Empties the contents of an entity without deleting the entity itself.
