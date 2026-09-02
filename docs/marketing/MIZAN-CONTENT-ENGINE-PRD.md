# Mizan content engine — product requirements document

**Product type:** Internal content operating system
**Owner:** Marketing
**Partners:** Product, Engineering, Security, Design, Sales, Legal/Compliance
**Issued:** 2026-08-30
**Status:** Draft for definition review
**Initial channels:** Mizan website, technical papers, LinkedIn, GitHub, selected expert communities

---

## 1. Product decision

Mizan needs a content engine, not a posting calendar.

The engine must turn verified product truth and original technical thinking into a connected body of
work: one research artifact can become a white paper, architecture note, demo, diagram, LinkedIn
series, founder post, community contribution, sales follow-up, and learning signal without changing
the claim from one channel to another.

This PRD defines the workflow, information model, controls, and outputs. It does not prescribe whether
the team implements them with files in this repository, a CMS, an editorial tool, custom software,
or a combination. The team should start with the simplest system that meets the acceptance criteria.

---

## 2. Problem

Technical infrastructure companies lose trust when marketing moves faster than product truth. Mizan
has an additional burden: it sells control, evidence, and accountability. Its own public claims must
therefore be controlled, attributable, dated, and reviewable.

Without a content engine:

- product capabilities will be described differently by website, founder, sales, and engineering;
- roadmap will drift into present-tense copy;
- technical reviewers will find unsupported absolutes;
- long-form research will not generate a sustained publication sequence;
- community participation will look promotional rather than contributive;
- performance will be measured by impressions instead of technical conviction and evaluation intent;
- useful objections and failed claims will not flow back into product definition.

---

## 3. Objective

Create a repeatable system that can publish technically credible, visually coherent, claim-safe Mizan
content every week while preserving a chain from source evidence to public statement to audience
response.

The first operating target is:

> Publish one flagship technical paper and derive a six-week expert-audience campaign that produces
> at least ten substantive technical conversations, five architecture reviews, and three qualified
> controlled-agent evaluations—without a material claim correction after publication.

This is a hypothesis and campaign target, not a revenue forecast.

---

## 4. Users

| User | Job to be done |
|---|---|
| Product owner | Define what is true now, what is planned, and what must not be claimed. |
| Technical author | Build a rigorous argument from primary sources, product artifacts, and experiments. |
| Engineer/security reviewer | Verify mechanisms, limits, threat assumptions, examples, and benchmark wording. |
| Designer | Convert one argument into consistent diagrams, paper layouts, carousels, and motion assets. |
| Marketing editor | Adapt one source artifact to each channel without losing truth or specificity. |
| Founder/executive | Publish a personal point of view with evidence and clear product affiliation. |
| Sales engineer | Find the most relevant artifact for an objection or use case. |
| Community owner | Contribute useful work in a forum while following its rules and norms. |
| Analyst | Connect content consumption to meaningful technical and commercial outcomes. |

---

## 5. Operating principles

1. **One source, many expressions.** Derivatives point back to a canonical artifact and claim set.
2. **Claims are product objects.** They have maturity, evidence, owners, dates, and prohibited variants.
3. **Demonstration precedes promotion.** A technical claim should have an inspectable artifact whenever
   practical.
4. **Teach the category before pitching the company.** Most content should remain useful if the Mizan
   product paragraph is removed.
5. **Primary sources over citation theater.** Standards, regulators, specifications, research papers,
   and product documentation are preferred.
6. **Disclose limits where the claim appears.** A hidden legal footer does not correct a misleading hero.
7. **Community participation is contribution, not distribution arbitrage.** Do not cross-post promotional
   copy into expert forums.
8. **Earned attention before paid amplification.** Promote only content that produces the intended
   audience behavior organically.
9. **Objections are research input.** Repeated disagreement should update the paper, product, or position.
10. **Do not automate authority away.** Drafting may be assisted; factual approval and external publishing
    remain accountable human actions.

---

## 6. Content architecture

```text
Product truth + experiments + primary sources + audience questions
                              |
                              v
                    Canonical content brief
                              |
                  claim set + evidence packet
                              |
                              v
                     Anchor publication
               (paper / lab / architecture note)
                              |
        +---------------------+----------------------+
        |                     |                      |
        v                     v                      v
    LinkedIn              Website/docs          Communities
 page + founder        article + diagrams      contribution + lab
        |                     |                      |
        +---------------------+----------------------+
                              |
                              v
                  questions, objections, intent
                              |
                              v
                   product and claim updates
```

The canonical hierarchy is:

1. **Research/evidence packet** — sources, experiments, product artifacts, counterarguments.
2. **Anchor artifact** — the fullest reviewed expression of an argument.
3. **Derivative asset** — channel-specific expression linked to the anchor.
4. **Distribution record** — where, when, by whom, under which version and disclosure.
5. **Response record** — meaningful engagement, objection, question, or evaluation intent.
6. **Learning decision** — continue, revise, answer, test, or retire.

---

## 7. Content object model

### 7.1 Claim

Required fields:

- claim ID and exact approved wording;
- subject and audience;
- maturity: Shipped, Technical Preview, Roadmap, Research, or Absent;
- scope and exclusions;
- backing product version and artifact links;
- external sources, if any;
- claim owner and technical reviewer;
- last verified and review-by dates;
- permitted paraphrases;
- prohibited wording;
- correction history.

### 7.2 Content brief

Required fields:

- audience and one desired belief change;
- audience's strongest existing belief;
- problem, thesis, mechanism, proof, limitation, and next action;
- canonical claims used;
- primary sources and product artifacts;
- strongest counterargument;
- channel derivatives planned;
- author, reviewers, decision owner, due date, and status;
- success metric and stop rule.

### 7.3 Artifact

Required fields:

- artifact ID, title, type, canonical/derivative relationship;
- content version and product release represented;
- draft/review/approved/published/retired state;
- source claim IDs;
- author, factual approver, brand approver, publisher;
- publication URL and date;
- downloadable source and rendered versions where relevant;
- disclosure and correction notice;
- campaign and audience tags.

### 7.4 Audience response

Required fields:

- artifact/channel association;
- target-role classification where voluntarily known;
- question, objection, reproduction result, or requested next step;
- substantive versus vanity engagement;
- owner and follow-up state;
- product/claim/editorial learning tags;
- consent and privacy basis for any personal information retained.

---

## 8. Workflow

### 8.1 Discover

Inputs:

- product changes and falsification tests;
- customer and prospect questions;
- failed demos and security-review objections;
- new standards, regulator guidance, and peer-reviewed research;
- competitor mechanism claims;
- community discussions where Mizan can add original evidence.

Output: a ranked idea with a target audience, belief change, and evidence path.

### 8.2 Define

Create the canonical brief and answer:

1. What is the single argument?
2. What does the audience already believe?
3. What observable fact or demonstration could change that belief?
4. Which Mizan claims are relevant and what is their maturity?
5. What is the strongest counterargument?
6. What would make the content useful without the product pitch?
7. Which response would count as evidence of interest?

### 8.3 Research

- prefer primary/official sources;
- capture title, publisher, author, URL, date accessed, relevant section, and permitted quote length;
- distinguish source fact, Mizan inference, and Mizan opinion;
- reproduce product experiments against a named release/environment;
- include negative or ambiguous results;
- record competitor claims as that vendor's claims, not verified facts, unless independently tested.

### 8.4 Draft

Draft the anchor artifact before short-form derivatives. Each technical argument should follow:

```text
Problem -> consequence -> control model -> mechanism -> demonstration -> limits -> next question
```

The opening must not begin with Mizan's feature list. The product appears when the control model has
made the need understandable.

### 8.5 Review

Every anchor artifact requires:

- product truth review;
- engineering/security mechanism review;
- source and quotation review;
- claim-state review;
- brand/readability review;
- legal/compliance review only where regulatory, customer, certification, comparative, or privacy
  claims require it;
- final accountable approval by a named human.

Review comments must distinguish blockers from preferences.

### 8.6 Derive

After anchor approval, generate channel assets from its argument and claim set. Derivatives may shorten
or change the hook, but may not broaden the claim. Every derivative links to the most useful proof,
not automatically to a lead form.

### 8.7 Publish

Before publishing:

- recheck current product/claim status;
- apply channel-specific disclosures and community rules;
- confirm links, images, alt text, mobile rendering, authorship, and tracking;
- record artifact version, publisher, URL, and timestamp;
- prepare an owner to answer technical questions for the first 24 hours.

External publishing is a human-confirmed action. The system may prepare or schedule a post only after
the accountable publisher has approved the exact rendered content and destination.

### 8.8 Learn

Within five working days, record:

- which target roles engaged;
- the highest-quality questions and objections;
- which proof artifacts were opened, downloaded, or run;
- architecture/evaluation requests;
- statements that created confusion;
- claims needing correction or better support;
- the next content or product experiment.

---

## 9. Functional requirements

### 9.1 Source and claim governance

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-001 | P0 | Maintain a canonical claim registry. | Every material present-tense capability statement maps to an approved claim and backing artifact. |
| CE-002 | P0 | Synchronize capability status with the module ledger. | A capability status change creates a content-review task for affected artifacts. |
| CE-003 | P0 | Preserve source metadata and access date. | Reviewer can reach the direct supporting source from the content record. |
| CE-004 | P0 | Distinguish fact, inference, opinion, forecast, and product claim. | Draft/review UI or template visibly marks each category. |
| CE-005 | P0 | Flag prohibited or high-risk wording. | “Only,” “unique,” “complete,” “tamper-proof,” compliance guarantees, unsupported performance, and unlabeled roadmap claims block approval. |
| CE-006 | P0 | Track claim expiry/review dates. | Published content using expired claims enters review and cannot be repromoted without reapproval. |
| CE-007 | P1 | Provide an affected-artifact view for each claim. | A correction owner can identify every page, paper, post, deck, and snippet using the claim. |
| CE-008 | P0 | Cross-repository claims carry that repository's CI evidence. | A Memtara claim names a green run on `memtara-zkp` `main` at a stated SHA (its `evidence-v1` branch has never run in CI as of 2026-08-31); no claim may cite a laptop result. |
| CE-009 | P0 | Retired products and withdrawn claims are registry entries with state *Absent/Prohibited*. | “AIHOOTS”, “three-product bundle”, “18-month ZKP head start”, “delegated leases”, “CBUAE-ready” block approval wherever they appear, including founder posts. |

### 9.2 Brief and editorial backlog

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-010 | P0 | Capture the canonical brief fields in Section 7.2. | Work cannot enter drafting without audience, belief change, evidence path, counterargument, and owner. |
| CE-011 | P0 | Rank work by audience value, evidence strength, strategic fit, derivative potential, effort, and timeliness. | Editorial meeting can explain why each top item outranks the next. |
| CE-012 | P0 | Expose work state and accountable owner. | No artifact remains “in progress” without owner, next action, and review date. |
| CE-013 | P1 | Link repeated audience questions to proposed content. | Three similar objections create or raise the priority of an answer artifact. |
| CE-014 | P1 | Support campaign-level goals and stop rules. | Assets are evaluated as a connected argument, not independent impression contests. |

### 9.3 Authoring and review

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-020 | P0 | Author long-form and short-form content with shared claim references. | Approved derivatives retain source claim IDs and canonical artifact link. |
| CE-021 | P0 | Support role-based review and named final approval. | Product/security blockers cannot be cleared by the author who created the claim. |
| CE-022 | P0 | Show text and visual changes between review versions. | Approver can see whether a revision changed meaning, scope, diagram, data, or CTA. |
| CE-023 | P0 | Store approval against the exact rendered version. | Post-publication edits create a new version and correction/reapproval state. |
| CE-024 | P0 | Require alt text, source captions, and readable chart labels. | Accessibility fields are complete before publish approval. |
| CE-025 | P1 | Provide reusable approved snippets and diagrams. | Reuse preserves source version and does not create detached copy. |
| CE-026 | P1 | Permit AI-assisted drafting with provenance. | Generated text is marked during drafting and cannot bypass factual/human approval. |

### 9.4 White-paper production

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-030 | P0 | Support a canonical paper in web and downloadable form. | Web/PDF versions share content version, sources, date, and correction state. |
| CE-031 | P0 | Publish references and artifact links. | Reader can inspect cited standards, sample policy, evidence bundle, verifier, and experiment method. |
| CE-032 | P0 | Separate conceptual architecture from shipped Mizan architecture. | Diagrams and captions label reference model, current product, and future direction. |
| CE-033 | P0 | Include limitations and counterarguments as first-class sections. | Reviewer cannot approve a paper that presents unresolved thesis claims as findings. |
| CE-034 | P1 | Offer print-ready, screen-readable, and presentation derivatives. | Technical diagrams remain legible in A4/Letter PDF, mobile web, and 16:9 slides. |
| CE-035 | P1 | Version corrections transparently. | Material change produces dated correction note and preserves prior version reference. |

### 9.5 LinkedIn operations

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-040 | P0 | Maintain approved Page identity, overview, tagline, imagery, website, location, and admin ownership. | At least two accountable admins exist; organization details and links are complete. |
| CE-041 | P0 | Support Page and founder voices as distinct derivatives. | Company posts explain product/research; founder posts carry personal thesis and disclose affiliation. |
| CE-042 | P0 | Preview final post, carousel, document, alt text, links, and attribution before approval. | Publisher approves the exact destination-specific rendering. |
| CE-043 | P0 | Track post-to-anchor relationships. | Every technical post links or refers to its paper, lab, diagram, or source note. |
| CE-044 | P1 | Support a Page newsletter when platform eligibility is met. | Newsletter has one scope and cadence; first edition is an anchor article, not a company announcement. |
| CE-045 | P1 | Support employee/founder amplification without coordinated inauthentic engagement. | Team receives optional context and suggested commentary, never instructions to copy comments or manipulate reactions. |
| CE-046 | P1 | Track target-role and high-intent response. | Reporting separates impressions/reactions from technical questions, artifact use, architecture requests, and evaluations. |

### 9.6 Community participation

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-050 | P0 | Maintain a community register with topic fit, rules, contact, format, and contribution history. | Owner reviews rules immediately before each submission. |
| CE-051 | P0 | Require a community-native value statement. | Submission explains what members can inspect, learn, reproduce, or challenge without requiring a sales call. |
| CE-052 | P0 | Require affiliation disclosure. | Product/company relationship is visible wherever Mizan is discussed. |
| CE-053 | P0 | Prevent simultaneous copy-paste promotion. | The same text is not posted across expert communities; each contribution fits local norms. |
| CE-054 | P0 | Staff technical response after submission. | A qualified author monitors and answers in good faith during the active discussion window. |
| CE-055 | P1 | Support contribution before promotion. | Tier-1 community work includes reviews, open samples, threat cases, or research—not only links to Mizan. |
| CE-056 | P1 | Archive objections and reproduction reports. | Community feedback becomes a tracked product, claim, or follow-up content decision. |

### 9.7 Distribution and promotion

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-060 | P0 | Create channel-specific publication packages. | Package contains final copy, asset, alt text, link, disclosure, owner, timing, and response plan. |
| CE-061 | P0 | Require exact-content approval before any external publish action. | Destination, account, time, text, asset, and link are visible to the accountable publisher. |
| CE-062 | P0 | Preserve UTM/campaign attribution without exposing personal or sensitive data. | Analytics can tie artifact to qualified action and honors consent/retention rules. |
| CE-063 | P1 | Gate paid amplification on organic signal quality. | Content must meet a predeclared target-role or high-intent threshold before spend. |
| CE-064 | P1 | Support account/role-focused promotion. | Paid audience and landing page match a defined role and use case; broad awareness is not the default. |
| CE-065 | P1 | Record spend and downstream outcome. | Review shows cost per qualified architecture review/evaluation, not only CPM or clicks. |

### 9.8 Analytics and learning

| ID | Priority | Requirement | Acceptance condition |
|---|---:|---|---|
| CE-070 | P0 | Define one intended action per artifact. | Performance report states whether the artifact was designed for comprehension, proof use, discussion, or evaluation. |
| CE-071 | P0 | Capture meaningful response types. | Technical question, verifier run, repository interaction, architecture request, and qualified evaluation are distinct events. |
| CE-072 | P0 | Connect learning to decisions. | Every campaign review records continue, revise, test, retire, or product escalation with owner. |
| CE-073 | P1 | Support cohort comparison by role, topic, and artifact. | Team can identify which argument moved which target audience toward which action. |
| CE-074 | P1 | Detect message confusion. | Repeated category or capability misunderstanding opens a narrative defect against the owning surface. |

---

## 10. Roles and authority

| Decision | Accountable owner | Required reviewers |
|---|---|---|
| Product capability claim | Product | Engineering owner, module-ledger owner |
| Security mechanism or limitation | Security/Engineering | Product, technical editor |
| Regulatory interpretation | Legal/Compliance or qualified adviser | Product, marketing; cited primary source required |
| Comparative claim | Business/Marketing | Product, technical reviewer, legal if material |
| Brand and visual release | Design | Marketing, accessibility reviewer |
| White-paper publication | Marketing lead | Product, engineering/security, sources, design |
| Company Page publication | Authorized Page admin | Artifact owner and required factual reviewers |
| Founder publication | Named founder | Factual reviewer for technical/product claims |
| Community submission | Named contributor | Community owner and factual reviewer |
| Material correction | Original accountable publisher | Claim owner and affected-channel owners |

No author may self-approve a new product, security, performance, compliance, or comparative claim.

---

## 11. Editorial portfolio

The content mix should be deliberately narrow for the first 90 days:

| Pillar | Core question | Evidence form | Target share |
|---|---|---|---:|
| Authority at the action boundary | What is this agent allowed to do now? | Architecture, decision examples, policy lab | 30% |
| Human authority without approval theater | How is consent bound to the exact action? | Mutation/reuse experiments, approval patterns | 20% |
| Evidence that can disagree with the vendor | What can another party verify? | Bundles, verifier, tamper lab, limitations | 20% |
| Regulated agent deployment | How do controls enable real financial workflows? | Use cases, control mappings, pilot learning | 15% |
| Engineering in public | What failed, changed, or remains unproven? | Benchmarks, ADRs, falsification results | 15% |

Product announcements are not a pillar. They should be expressed through a customer problem, a
mechanism, and evidence.

---

## 12. Six-week anchor campaign

The first campaign is based on the paper **From Guardrails to Authority: Controlling AI Agents at the
Action Boundary**.

### Week 0 — foundation

- approve Page identity and company overview;
- publish the technical front door and capability/maturity page;
- publish sample architecture, policy, bundle, and verifier path;
- prepare founder and engineering profiles with accurate Mizan affiliation;
- validate community rules and assign response owners.

### Week 1 — category problem

- publish the white paper on Mizan's website;
- company post: the control gap between model output and tool execution;
- founder post: why “the agent had access” is not a sufficient authorization decision;
- invite direct technical critique, not demos.

### Week 2 — architecture

- publish the action-boundary diagram and technical note;
- company carousel: IAM, guardrails, action control, and evidence as complementary layers;
- contribute a framework-neutral threat/control example to an appropriate expert community.

### Week 3 — approval integrity

- publish the exact-request approval lab;
- engineering post: approve once, execute once, reject mutation;
- host a small architecture clinic for 6–10 invited practitioners.

### Week 4 — evidence

- publish the offline evidence/tamper lab;
- company post: what the verifier proves and does not prove;
- invite auditors/security reviewers to run it without Mizan present.

### Week 5 — regulated use case

- publish the wealth/financial-action walkthrough with synthetic data (Mizan-only until workplan
  T-133–T-137 merge; the proof-gated suitability variant, catalogue UC-2, may not be shown as one
  transaction before then);
- founder post: proportional autonomy—safe reads continue, consequential writes wait;
- direct outreach to qualified UAE/GCC agent program owners with the relevant artifact.

### Week 6 — open review

- publish questions, objections, failed assumptions, and corrections;
- submit a Show HN only if the lab is genuinely self-service and meets the community's guidelines;
- review the campaign against technical conversations, proof use, architecture reviews, and qualified
  evaluations;
- choose the next paper from observed questions.

---

## 13. Community strategy

The current recommended order is:

| Tier | Community | Why it fits | Contribution before promotion |
|---:|---|---|---|
| 1 | [OWASP GenAI Security Project](https://genai.owasp.org/contributing/) and Agentic Security Initiative | Open technical work on agentic security, risks, samples, and guidance. | Offer a framework-neutral action-authorization test case, approval-binding abuse case, or evidence-verification lab; participate in review. |
| 1 | [Cloud Security Alliance AI Safety Working Group](https://cloudsecurityalliance.org/research/working-groups/ai-safety) | Security, governance, assurance, and lifecycle guidance with practitioners and researchers. | Join working sessions, review research, and contribute a control/evidence pattern rather than a product pitch. |
| 1 | [AI Village](https://aivillage.org/) | Hands-on public-interest AI security, workshops, labs, red teaming, and field notes. | Provide a safe lab or challenge demonstrating authority escalation, request mutation, or evidence tampering. |
| 1 | Mizan GitHub technical commons | Lets experts inspect artifacts and reproduce claims on Mizan-controlled ground. | Publish samples, verifier, threat cases, clear contribution guide, issues/discussions, and versioned results. |
| 2 | [Hacker News Show HN](https://news.ycombinator.com/showhn.html) | Strong technical feedback when there is something people can actually try. | Submit only a working self-service lab or open tool; founders remain available for candid technical discussion. |
| 2 | Relevant Reddit communities such as r/netsec, r/AI_Agents, and r/AI_Governance | Useful for specific questions and practitioner feedback, but norms and moderation vary. | Ask a narrow technical question, publish methods and failures, disclose affiliation, and verify each community's current rules immediately before posting. |
| 2 | Financial-services security and AI working groups | Direct access to the regulated problem, often membership or relationship based. | Share anonymized control patterns and seek peer review; do not use member spaces as lead lists. |

Do not enter all communities at once. Earn context in two Tier-1 communities, contribute useful work,
and expand only when the team can sustain replies and follow-through.

NIST's current [AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
and [identity and authority work](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
also provide a strong agenda for technical content. Treat government/standards engagement as public
technical contribution, not a promotional channel.

---

## 14. LinkedIn Page requirements

LinkedIn permits free company Pages, requires an authorized personal profile to create one, and
supports assigned admin roles. The setup owner should follow current
[LinkedIn Page creation guidance](https://www.linkedin.com/help/linkedin/answer/a543852/creating-a-linkedin-company-page?lang=en)
and complete all relevant fields; LinkedIn says complete Page information improves discoverability.

### Required Page package

- Page name: **Mizan** unless trademark/domain review requires a qualifier;
- public URL: reserve the closest defensible `mizan` handle;
- tagline: **Control before action. Proof after.**;
- category/industry chosen for enterprise software/cybersecurity fit;
- concise overview from the launch editorial pack;
- website, Dubai/UAE location if factually appropriate, company size, and company type;
- logo, accessible profile image, and banner derived from the action-boundary visual;
- two super admins and at least one content admin with documented recovery ownership;
- initial six posts approved before the Page is promoted;
- comment and inquiry response ownership;
- analytics baseline recorded on launch day.

A Page newsletter can follow when Mizan meets access criteria. LinkedIn currently supports Page
newsletters for eligible Pages with super/content admins and notifies Page followers when the first
edition is published; see [LinkedIn's current newsletter guidance](https://www.linkedin.com/help/linkedin/answer/a596833).
The proposed title is **The Action Boundary**.

### Voice division

**Company Page:** precise diagrams, mechanisms, release truth, papers, labs, customer problems, and
team work.
**Founder:** personal conviction, hard decisions, lessons, dissent, category interpretation, and direct
conversation.
**Engineering/security authors:** methods, code/artifacts, results, limitations, and responses to
technical critique.

The company Page should not merely repost founder copy. Each voice has a different job.

---

## 15. Measurement model

### Primary outcomes

- target-role technical conversations;
- architecture-review requests;
- sample artifact downloads and verifier runs;
- qualified evaluations with a named agent and tools;
- community reproductions, corrections, or substantive critique;
- product changes caused by audience learning.

### Secondary indicators

- target-role follows/subscriptions;
- saves, long comments, and shares containing interpretation;
- paper completion and architecture-page depth;
- return visits to technical artifacts;
- direct mentions by credible practitioners.

### Vanity indicators

- total impressions;
- raw reactions;
- generic follower growth;
- undifferentiated traffic;
- low-context lead form fills.

Vanity indicators may help diagnose distribution. They cannot justify a content strategy by themselves.

---

## 16. Safety, legal, and trust requirements

- Use synthetic or explicitly authorized customer data only.
- Never publish credentials, internal endpoints, exploitable deployment details, or uncoordinated
  vulnerability information.
- Obtain written permission for customer names, quotes, metrics, and logos.
- Cite regulatory text directly and avoid implying endorsement or certification.
- Respect source copyright and quotation limits; link and paraphrase when possible.
- Disclose Mizan affiliation in comparative, community, and research discussions.
- Keep contact and behavioral data to the minimum required, with defined access and retention.
- Maintain a visible correction route and correct material errors in every affected channel.
- Do not purchase followers, coordinate artificial engagement, scrape member lists, or automate
  unsolicited direct messages.
- Do not create fear-based incident claims that exceed the demonstrated control boundary.
- Do not name AIHOOTS, quote an AIHOOTS metric, or describe a three-product bundle in any channel.
- Do not quote a Memtara metric or regulatory-readiness statement; the only sayable Memtara claims are
  the four rows marked *Sayable* in `docs/business/MIZAN-COMMERCIAL-STRATEGY.md` §2.

---

## 17. Launch acceptance

The content engine is ready for its first campaign when:

1. the claim registry covers all claims used by the front door and paper;
2. the flagship paper passes technical, source, claim, design, and final publication review;
3. web and PDF versions are versioned and accessible;
4. all derivative posts trace to the canonical artifact and approved claims;
5. the LinkedIn Page package, admin ownership, and first six posts are ready;
6. the technical response owner can answer during every planned launch window;
7. at least one Tier-1 community contribution is useful without clicking through to Mizan;
8. analytics distinguish target actions from vanity engagement;
9. correction, retirement, and affected-artifact workflows have been rehearsed;
10. promotion stops automatically if a material product-truth or security issue appears.

---

## 18. Non-goals for the first version

- fully autonomous content generation or publishing;
- high-volume SEO article production;
- publishing to every social network;
- personalized cold-message generation;
- replacing product documentation, CRM, or issue tracking;
- summarizing sources the team has not reviewed;
- becoming a general-purpose brand asset manager;
- optimizing for daily post volume;
- paid demand generation before technical message/product gates pass.

---

## 19. Definition of done

The first version is complete when the team can take one verified product thesis and, through a
controlled and inspectable workflow, publish:

- one canonical white paper;
- one web article and technical architecture page;
- one reproducible lab or evidence artifact;
- one design system for the paper, diagrams, and carousels;
- six company Page posts;
- six founder/engineering posts;
- one Page identity package;
- two community-native contributions;
- one architecture-review invitation;
- one campaign review that connects audience response to a product, claim, or editorial decision.

The result should feel less like a marketing machine and more like a disciplined technical publication
that happens to be building the product it studies.
