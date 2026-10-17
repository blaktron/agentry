# Authorization evidence

The API authorization family keeps tests at separate boundaries: route
registration, HTTP authorization, resource visibility, extension answers,
current principals and the signing worker. Similar caller names do not make
these contracts interchangeable. The named inventory records all nine files
and sixteen top-level tests in this family.

## Retained assertions

Each row includes the cases inside the test,
including cases expressed as loops rather than named subtests.

| Test | Retained contract and cases |
| --- | --- |
| `TestRouteDeclarationsComplete` | Spec operations and actual mounted patterns agree in both directions; declarations exist, gates and rate classes are known, public/sentinel declarations explain their exposure, and no declaration names an unserved route. Git mounts enter through the real mount function. |
| `TestExtensionMountIsDeclaredByPrefix` | Extension root and child patterns declare a principal gate with a reason; an unrelated unknown pattern remains undeclared. The core completeness fixture loads no extension. |
| `TestAuthzMatrix` | Every eligible operation has a request factory. Anonymous, admin, reviewer, active member, pending member, outsider, broad PAT, wrong-scope PAT and sign-in-grant PAT exercise real HTTP. Destructive cases keep disposable targets or defer sessions to lifecycle tests; hidden organization routes demand exact 404 for outsiders. |
| `TestSelfAuthorizedMatrix` | Every self-authorized operation has a case. Platform and organization queues, loaded review items/files/findings, staff and non-staff, staff authors, unrelated organization admins, scoped/unscoped staff PATs, session-only model-input calls and invitations retain their distinct truth-table rows. |
| `TestAgentReadSeamAnswersAsTheCoreDoes` | Ten caller classes cross three real agents: organization private/public and founder private. Literal read decisions agree with the HTTP agent route; the returned reference is correct. Suspension hides both organization agents, the founder's own agent remains readable, decommission permits reads, and missing agent/namespace return 404. |
| `TestAgentMaintainSeamAnswersAsTheCoreDoes` | Eleven caller classes cross the same three visibility/namespace dimensions. Literal maintain decisions agree with settings visibility in the agent response. Read versus maintain grants and PAT scope differ; the returned reference, decommission/suspension write refusals, unaffected founder agent and missing targets remain checked. |
| `TestAgentPublishSeamAnswersAsTheCoreDoes` | Ten caller classes cross the same three dimensions. Literal publish decisions agree with `canPublish`, which is true or absent. A maintain grant cannot publish; a publish grant can. The sign-in-like PAT publishes without seeing maintain settings; reference, decommission write refusal, unaffected founder agent and missing target remain checked. |
| `TestSignInGrantTakesTheOwnerActions` | Real published history: private/public, retire/restore, response fields, five settings-only or mixed PATCH refusals without changing visibility, grants refusal, typed-name requirement, tombstone deletion and subsequent owner 404. A generic matrix allowance is not these state transitions. |
| `TestAgentManageKeepsTheAdministratorsRung` | Member and outsider sign-in tokens are refused all four owner actions on an actual organization agent. Its admin takes visibility, retire, restore and hard delete with no version history. Scope does not confer the administrator rung. |
| `TestPrivateAgentInvisibleToNonReaders` | Anonymous and actual stranger receive a missing name's normalized problem document for metadata, versions and advisories; writes are 404, listings hide the name, the owner reads it, and public read/write answers stay 200/401. |
| `TestPrivateOrgAgentReaderSetIsEveryActiveMember` | Active member reads the real private agent. Pending member, outsider and anonymous receive the missing name's same normalized 404 document. This checks response equivalence, beyond matrix authorization denial. |
| `TestMembershipConfersPublishButNotTheAgentItself` | Member creates private and changes summary; exposure, deletion, grants/listing, public creation and force-push settings remain the admins'. Admin succeeds at the corresponding operations; pending member creates nothing. Exact refusal details remain checked where present. |
| `TestPrincipalForUserAnswersTheRoleAsItIsNow` | Seven users × three agents × three actions compare current-by-id and session answers, with literal discriminator cases and both allow/deny required. Removed membership and grants disappear, founder remains authorized, hold refuses writes, suspended/missing users have no principal, and identity fields carry no credential or SSO freshness. |
| `TestPrincipalForScheduleIsTheOwnersNarrowCredential` | Current owner role plus fixed schedule scopes, schedule/account ids, verified identity and no session/PAT/staff/SSO. Read succeeds; maintain/publish fail. User principal stays unchanged; nil schedule, missing and suspended owner are refused. |
| `TestKeylessRoleStartsWithoutTheKeyAndServesWhatTheWorkerSigned` | Real key holder and keyless twin serve the same active key; the served ruleset envelope verifies against it. A key-holding server fails startup without its key. |
| `TestKeylessApprovalIsPublishedAndSignedByTheWorker` | Keyless approval leaves review pending publication and queues one job; stale conflicting decision fails; the worker publishes a verifiable envelope. Lost enqueue is recovered only by the key holder; an approval never handed off remains unpublished. |

The generic matrix tests wiring against route declarations and the auth
chokepoints. Its expected answer calls `auth.Check` or `auth.CheckAgent`;
`TestCheckTruthTable`, `TestCheckPATScopes`, `TestNamespaceDerivedAgentRole`,
`TestAgentRoleLadder` and `TestAgentManageScope` in `internal/auth` pin the
rules independently. The three agent-seam tests above also retain literal
expected decisions. Keep both owners; calculating an expectation through the
chokepoint is not independent evidence that the chokepoint's rule is correct.

The generic matrix uses one organization and its public agents. A random or
zero id is a missing resource, not an actual foreign resource. The private
agent cases and seam grids above retain actual resources a caller does not
own. `TestSharedKnowledgeIsHiddenFromOutsiders` additionally uses another
organization's admin and member against ten real shared-knowledge routes,
including the real pack and its bytes; its family owns that tenant boundary.

## Caller fixtures

The read, maintain and publish seam tests use `seedCaller` for ordinary
founders, pending members, reviewers, outsiders and grant holders. Their
requests still pass through the real session, CSRF and authorization
middleware. Each test keeps its own server and objects; fixtures are not
shared between these three permission contracts.

The read test reuses one real member session for its two PAT issuances and
its read grid. The seeded accounts share one real password hash per process
with other `seedCaller` fixtures. Seeding callers saves setup work only; it
removes no permission case.

Members still register and join through the invitation endpoints. Staff still
register, receive the staff fixture flag and sign in. Organization creation,
grants, PAT issuance, suspension and all asserted requests retain their real
HTTP paths. The seeded accounts are active and verified; these tests do not
own the unactivated-account contract. `TestAuthLifecycle` keeps real
registration, password failure, session issuance, CSRF and logout evidence;
`TestUnactivatedAccountUntilActivated` keeps activation/refused-write evidence.

Other family fixtures remain: the generic matrix's per-operation disposable
resources, the self-authorized matrix's scanned review item and single-use
invitation, principal revocations and the keyless twin/worker. Their lifecycle
and failure assertions are not replaced by an ordinary-caller seed.

## Review authorization beside this family

Review-role evidence is also catalogued under publication. Retain
`TestOrgReviewQueueRequiresReviewer`: a member becomes admin and then reviewer,
and each real role change affects the queue answer. The empty organization
queue in the self-authorized matrix does not replace this transition.

Retain `TestReviewApprovalFlow` for non-staff author refusal on the platform
queue and the final version transition. `TestStaffReviewAnyOrganizationsQueue`
keeps non-staff author refusal on the organization's actual item, staff access
without membership, member refusal, global queue listing and audit direction.
`TestStaffDecideTheirOwnPlatformItem` and
`TestStaffAuthorRejectsTheirOwnOrganizationItem` keep staff self-decision audit
marks and the absence of a mark on another person's decision.

`TestAcceptedRiskOnOrgAgentReservedToOrgReviewers` and
`TestStaffSetFindingVerdictsOnAnOrganizationItem` keep protective verdicts
separate from accepting risk for an organization. `TestReviewItemOfAnUnknownQueueIsRefused`
forces a row past the database constraint to check the independent application
refusal and restores the constraint afterwards. Preserve its serialization.

`TestAnAuthorSetsNoVerdictOnTheirOwnFindings` holds the finding route to the
review decision's author rule: an organization's admin who submitted the
version is refused a verdict on its findings, and a staff author's verdict is
recorded with `self_decision` in its audit event.

Extension adapters exercised through bound `Deps` are a separate boundary;
the API probe tests here exercise the server seam, so they do not replace it.

The [coverage guide](testing.md) gives the consolidation and verification
rules.
