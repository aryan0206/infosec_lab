# Generated variations, not confirmed past questions

Try a grant question that changes `Grant ID` to `Expense ID` and adds a category search. Adapt `10_integrated_scenarios/grant_portal.py`: add the category to the signed canonical protected fields, persist it, and return only ID/category in the search result. Re-run tamper and persistence tests. Try a patient question asking for a *sum* over a selected diagnosis: filter IDs before encrypting values, then combine ciphertexts; validate the total below Paillier `n`. These are generated exercises, not past papers.
