# AI Usage Note

I used AI as a drafting and acceleration tool for:
- proposing a thin canonical event model
- outlining normalization rules and test cases
- drafting README structure and ServiceNow modeling notes

What AI helped with:
- speeding up boilerplate generation
- suggesting a practical split between normalization, storage, and tests
- helping turn the prompt into a review-friendly submission structure

What I validated or corrected:
- tightened the schema so it stayed reporting-friendly instead of overly nested
- simplified severity mapping to ensure deterministic outcomes
- corrected malformed-record handling so errors are quarantined rather than ignored
- kept ServiceNow integration at a credible design level rather than pretending to have a live instance

What I rejected:
- overly broad architecture that included unnecessary infrastructure for a timeboxed exercise
- unsupported claims about exact ServiceNow tables or vendor payload fidelity
- solutions that optimized for polish instead of data-quality behavior
